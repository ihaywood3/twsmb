# twsmb

A [twisted python](http://twistedmatrix.com/)
 server implementation of Microsoft's Server Message Block
network file access protocol.

## Limitations

The focus is on the "modern" 
[SMB2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962)
protocol (Windows Vista and later) running on
"direct TCP" (port 445). No support for old protocols like NetBIOS, WINS, etc.

Conversely in the first instance only the base protocol (2.02) is supported,
features like encryption will come later.

## Current Status

Completely useless: only one packet type parsed so far. Under active development.

## Prior Art

Mike Teo's [pysmb](https://miketeo.net/wp/index.php/projects/pysmb) is a pure
Python SMB client library, including twisted support.