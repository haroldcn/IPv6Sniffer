================================================== ==============================
MICROSOFT Foundation Class Library : mcf6 Project Overview
================================================== =============================

Application Wizard has created this mcf6 application for you . This application not only demonstrates the basics of using the Microsoft Foundation Classes , but also as a starting point for writing your application .

This document provides an overview of the content of the composition mcf6 application of each file.

mcf6.vcproj
It is generated using an application wizard master project file VC + + project .
Version of the file that contains the generated Visual C + + , and platform choice about using the Application Wizard , configuration, and project features .

mcf6.h
This is the main header file for the application . It includes other project specific headers ( including Resource.h), and declares Cmcf6App application class.

mcf6.cpp
This is included in the main application class Cmcf6App application source files.

mcf6.rc
This is a list of programs to use all of the Microsoft Windows resources. It includes icons stored in the RES subdirectory , bitmaps, and cursors. This file can be edited directly in Microsoft Visual C + + . Project resources are in 1033 .

res \ mcf6.ico
This is used as the application icon icon file. This icon is included by the main resource file mcf6.rc in .

res \ mcf6.rc2
This file contains not in Microsoft Visual C + + for editing resources. You should not editable by the resource editor for all resources on this file.


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Application Wizard to create a dialog class :

mcf6Dlg.h, mcf6Dlg.cpp - Dialog
These files contain Cmcf6Dlg classes. This class defines the behavior of the application's main dialog . Located mcf6.rc the dialog template , the file can be edited in Microsoft Visual C + + in .


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Other features:

ActiveX Controls
Applications include support for the use of ActiveX controls.

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Other standard files :

StdAfx.h, StdAfx.cpp
These files are used to build a mcf6.pch precompiled header (PCH) file and a precompiled types file named StdAfx.obj .

Resource.h
This is the standard header file , which defines new resource ID.
Microsoft Visual C + + reads and updates this file.

mcf6.manifest
Application manifest file for Windows XP is used to describe applications
Parallel dependent on a specific version of the assembly. Loader uses this
Information load the appropriate assembly from the assembly cache or
Load private information from the application. For a list of possible applications and redistributed as
And application executable files are installed in the same folder outside . Manifest file includes ,
May also be in the form of resources included in the executable file.
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Other notes :

AppWizard uses "TODO:" instruction should add to or customize the source code section.

If your application uses MFC in a shared DLL , you need to re- publish the MFC DLL; If the language used in the application area with the current set different operating system , you also need to re- release the corresponding localized resources MFC90XXX.DLL. For more information on these topics , see the MSDN documentation on Redistributing Visual C + + applications ( re-released Visual C + + application) chapters .

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////