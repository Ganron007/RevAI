## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=32519b85c0b422e4 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=DOTNET, entropy=92, sha256=32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77
  Anomalies (13): BigStaticArray (resources), BigStringHiScore×34 (strings), DllNoExportTable (exports), DotnetCryptoApiUsage×10 (imports), DotnetDynamicLoadingApiUsage×3 (imports), ExternalModule×3 (imports), ImportByHash (imports), ManyBase64Strings×118 (strings), ManyUniqueImmediateBytes×7 (code), NativeMethods×7 (imports), SpaghettiFunction×4 (code), StringBase64×70 (strings), XorInLoop×8 (code)
  High-signal anomaly locations: BigStaticArray@1000756; DotnetCryptoApiUsage@147702,147368,147336; DotnetDynamicLoadingApiUsage@258120,7274,8822; ExternalModule@497326,497330,497334; ManyUniqueImmediateBytes@12792,78496,99292; NativeMethods@500146,500156,500166; SpaghettiFunction@78496,207692,214112; XorInLoop@12014,12450,264704
  YARA (info, 4 total): DotNet, VisualBasicDotNet, DownloadUsingWininet, ElevatePrivileges
  Functions (15): GetHive@265324, ComputeStringHash@264684, GetHash@12424, GetOrCreateUserID@11884, UpdateBuffer@279632, GetCache@274804, Deflate@274104, Inflate@274188, CreateSecureString@279208, CreateNewInterface@211460, CreateNodeInterface@207692, CreateInterface@214112, LoadCommandParams@240176, GenerateLambdaFilter@185500, GetActiveAlertFromDataRow@153336
  Top high-signal imports (score≥8, 194 of 4777):
    [10] SolarWinds.InformationService.Linq.Plugins.Core.Orion.DiscoveryLogs.set_ResultDescription ×6
    [10] SolarWinds.Orion.Core.Common.Models.Volume.get_VolumeDescription ×6
    [10] SolarWinds.Orion.Core.Common.ExpressionEvaluator.ExprEvalErrorDescription.get_InvalidText ×5
    [10] SolarWinds.Orion.Core.Common.Models.Node.get_NodeSubType ×5
    [10] SolarWinds.Orion.Swis.Contract.InformationService.SubscriptionOptions.set_Description ×5
    [10] System.Linq.Enumerable.OrderByDescending ×5
    [10] System.ServiceModel.Description.ServiceDescription.get_Endpoints ×5
    [10] System.ServiceModel.ServiceHostBase.get_Description ×5
    [10] SolarWinds.Orion.Core.Common.Models.Mib.Oid.set_Description ×4
    [10] SolarWinds.Orion.Core.Common.Models.Node.set_StatusDescription ×4
    [10] SolarWinds.JobEngine.JobDescription.set_LegacyEngine ×3
    [10] SolarWinds.JobEngine.JobDescription.set_SupportedRoles ×3
    [10] SolarWinds.Orion.Core.Common.Models.Alerts.ActiveAlert.set_RelatedNodeStatus ×3
    [10] SolarWinds.Orion.Core.Common.Models.Mib.Oid.get_Description ×3
    [10] SolarWinds.Orion.Core.Discovery.DataAccess.DiscoveryNodeEntry.GetCountOfNodes ×3
    [10] SolarWinds.Orion.Core.Models.Discovery.CoreDiscoveryPluginResult.set_DiscoveredNodes ×3
    [10] SolarWinds.Orion.Discovery.Job.OrionDiscoveryJobDescription.get_DiscoveryPluginJobDescriptions ×3
    [10] SolarWinds.Orion.ServiceDirectory.Wcf.ConnectionDescriptorToServiceEndpointMapperExtensions.Map ×3
    [10] SolarWinds.Serialization.Json.SerializationHelper.Deserialize ×3
    [10] SolarWinds.ServiceDirectory.Client.Contract.ServiceEndpointDescriptor.ctor ×3
    [10] SolarWinds.ServiceDirectory.Client.Contract.ServiceEndpointDescriptor.set_ConnectionDescriptor ×3
    [10] SolarWinds.ServiceDirectory.Client.Contract.ServiceEndpointDescriptor.set_ServiceEndpointProperties ×3
    [10] SolarWinds.JobEngine.JobDescription.ctor ×2
    [10] SolarWinds.JobEngine.JobDescription.get_LegacyEngine ×2
    [10] SolarWinds.JobEngine.JobDescription.set_EndpointAddress ×2
    [10] SolarWinds.JobEngine.JobDescription.set_JobDetailConfiguration ×2
    [10] SolarWinds.JobEngine.JobDescription.set_JobNamespace ×2
    [10] SolarWinds.JobEngine.JobDescription.set_ResultTTL ×2
    [10] SolarWinds.JobEngine.JobDescription.set_TargetNode ×2
    [10] SolarWinds.JobEngine.JobDescription.set_Timeout ×2
  Mid-signal imports: System.Net.NetworkInformation.Ping.Send, System.ServiceModel.Channels.Binding.set_SendTimeout, advapi32.OpenProcessToken
  (low-signal/noise imports: 4580 omitted)
  - Constants/registry (3): registry::HKEY_CURRENT_USER, registry::HKEY_LOCAL_MACHINE, registry::HKEY_USERS
  - Constants/crypto (1): crypto::PKCS_DigestDecoration_SHA256__8_byt_19×2
    Constants/apihash (1): apihash::hash(strstr)
    Constants/oid (36): oid::signedData, oid::sha-256, oid::spcIndirectDataContext, oid::spcPEImageData, oid::sha256WithRSAEncryption, oid::organizationName, oid::organizationalUnitName, oid::stateOrProvinceName
  Strings/urls (2 total): http://www.solar..?id=online_quote, http://www.solar..lang={0}&kb=3545
  Strings (other, 298 items, omitted)
  Carved files (1): PKCS7@1024520 (6990 bytes)
  Virtual files (1): VER/1/unk
  Recovered structures (60): MZ, PE, OptionalHeader, Sections, mscoree.FT, CLR.Header, CLR.Metadata, #~, ModuleTable, TypeRefTable, TypeDefTable, FieldTable, MethodDefTable, ParamTable, InterfaceImplTable

## capa evidence (58 total, showing top 15)
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (4): get common file path, check if file exists, enumerate files in .NET, get file version info
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (2): encode data using Base64, encrypt data using DPAPI
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (2): query environment variable, get hostname
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (2): query or enumerate registry key, query or enumerate registry value
  ATT&CK {'parts': ['Defense Evasion', 'Virtualization/Sandbox Evasion', 'System Checks'], 'tactic': 'Defense Evasion', 'technique': 'Virtualization/Sandbox Evasion', 'subtechnique': 'System Checks', 'id': 'T1497.001'} (1): reference anti-VM strings targeting VMWare
  ATT&CK {'parts': ['Collection', 'Archive Collected Data', 'Archive via Library'], 'tactic': 'Collection', 'technique': 'Archive Collected Data', 'subtechnique': 'Archive via Library', 'id': 'T1560.002'} (1): compress data using GZip in .NET
  ATT&CK {'parts': ['Defense Evasion', 'Deobfuscate/Decode Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Deobfuscate/Decode Files or Information', 'subtechnique': '', 'id': 'T1140'} (1): decode data using Base64 in .NET
  ATT&CK {'parts': ['Discovery', 'Process Discovery'], 'tactic': 'Discovery', 'technique': 'Process Discovery', 'subtechnique': '', 'id': 'T1057'} (1): enumerate processes
  ATT&CK {'parts': ['Discovery', 'Software Discovery'], 'tactic': 'Discovery', 'technique': 'Software Discovery', 'subtechnique': '', 'id': 'T1518'} (1): enumerate processes
  ATT&CK {'parts': ['Defense Evasion', 'Modify Registry'], 'tactic': 'Defense Evasion', 'technique': 'Modify Registry', 'subtechnique': '', 'id': 'T1112'} (1): delete registry value

## pe_imports (1 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (17)
  Rules: domain, IP, contains_base64, VMWare_Detection, url, NETDLLMicrosoft, IsPE32, IsNET_DLL, IsDLL, IsConsole, HasOverlay, HasDebugData, vmdetect, network_tcp_listen, network_dns, escalate_priv, win_token

## FLOSS strings (10906 total)
  (other strings, 80 items omitted)

<!-- evidence_assembler: used 7428/28000 chars across 5 tools -->