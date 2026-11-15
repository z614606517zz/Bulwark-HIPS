Unicode true
ManifestDPIAware true
RequestExecutionLevel admin

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "WinMessages.nsh"

Page custom TestCreate
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Var Dlg
Var Cb1
Var Cb2
Var Cb3

Function TestCreate
    !insertmacro MUI_HEADER_TEXT "Color Test" "Checkbox background test"
    nsDialogs::Create 1018
    Pop $Dlg
    SetCtlColors $Dlg 0xE2EAEF 0x131415

    ${NSD_CreateCheckbox} 10u 15u 90% 12u "AAAA SetWindowTheme + solid colors"
    Pop $Cb1
    System::Call 'uxtheme::SetWindowTheme(i, w, w) i ($Cb1, "", "")'
    SetCtlColors $Cb1 0xE2EAEF 0x131415

    ${NSD_CreateCheckbox} 10u 40u 90% 12u "BBBB solid colors only"
    Pop $Cb2
    SetCtlColors $Cb2 0xE2EAEF 0x131415

    ${NSD_CreateCheckbox} 10u 65u 90% 12u "CCCC no colors"
    Pop $Cb3

    nsDialogs::Show
FunctionEnd

Section
SectionEnd
