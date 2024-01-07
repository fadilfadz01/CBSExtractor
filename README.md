# CBSExtractor
Dump CBS update packages from Windows 10 Mobile image.

This program is technically made to extract or dump the CBS update packages from a Windows 10 Mobile device that has access to the Mass Storage Mode, or from a mounted Windows 10 Mobile image, and deploy it on another device that has an unlocked bootloader.

```
CBSExtractor 1.0.0.0
Copyright (c) 2024 - Fadil Fadz

  -d, --drive     Required. A path to the source drive to dump the CBS packages from.
                  Examples. D:\
                            D:\EFIESP

  -o, --output    Required. A path to the output folder to save the CBS packages dump.
                  Examples. C:\Users\User\Desktop\Output
                            "C:\Users\User\Desktop\CBS Dumps"

  -f, --filter    Optional. Dump only the given CBS packages.
                  Examples. Microsoft.MainOS.Production
                            Microsoft.MainOS.Production;Microsoft.MobileCore.Prod.MainOS;...

  -s, --sign      (Default: false) Optional. Test sign the output CBS packages.

  --help          Display this help screen.

  --version       Display version information.
```
