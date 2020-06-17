# Sophos SAVDI antivirus plugin for Moodle 3.2+

Copyright © 2017–2020 The University of Southern Queensland (https://www.usq.edu.au)

This plugin adds virus scanner support for the Sophos SAVDI daemon to Moodle 3.2 and newer. These scanner (SAVDI daemon) and web server combinations are supported:

* Scanner on the same host as the web server, web server files readable by the scanner. Requires 'allowscanfile' option be FILE, DIR, or SUBDIR in the scanner configuration. Connection may be via Unix domain socket or TCP/IP.
* Scanner on the same host as the web server, web server files *not* readable by the scanner. Requires 'allowscandata' be YES in the SAVDI configuration. Connection may be via Unix domain socket or TCP/IP.
* Scanner on a different host to the web server. Requires 'allowscandata' be YES in the SAVDI configuration. Connection is via TCP/IP, so ensure any relevant network and host firewalls allow communication with the daemon.

See the [Troubleshooting](#troubleshooting) section below for common deployment issues.

The Sophos Simple Scanning Protocol is documented in these references:

* https://www.sophos.com/en-us/medialibrary/PDFs/partners/savi_sen.pdf
* https://www.sophos.com/en-us/medialibrary/PDFs/documentation/savi_sssp_14_meng.pdf
* https://www.sophos.com/en-us/medialibrary/PDFs/documentation/SAVDI_User_Manual.pdf

See also the [Example savdid.conf](#example-savdid.conf) for an annotated "local to web server" SAVDI configuration.

## Troubleshooting

These error messages may be sent to administrators of the Moodle site.

### Could not open item passed to SAVI for scanning

The scanner could not directly open and read from the scan file on its filesystem. If the scanner is local to the web server, try enabling the "Change scan file permissions" setting. If the scanner is not local to the web server, enable the "SAVDI daemon is remote" setting.

### Scan terminated due to timeout

The scanner gave up scanning a file due to its 'maxscantime' threshold being exceeded.

### SAVDI server does not support request type SCANDATA

The scanner does not have the 'allowscandata' option enabled, which is required if the scanner is remote to the web server.

### Data size exceeds SAVDI server limit of _nnn_ bytes

The size of the file being scanned exceeded the 'maxscandata' limit configured in the scanner. A value of 0 for 'maxscandata' sets no limit.

## Example savdid.conf

Full documentation of this file can be found at https://www.sophos.com/en-us/medialibrary/PDFs/documentation/SAVDI_User_Manual.pdf.

    threadcount: 30
    maxqueuedsessions: 2
    virusdatadir: /opt/sophos-av/lib/sav
    idedir: /opt/sophos-av/lib/sav
    onexception: REQUEST
    onrequest: REQUEST

    log {
        type: FILE
        logdir: /var/log/savdi
        loglevel: 2
    }

    channel {
        commprotocol {
            type: UNIX
            socket: /var/run/savdid.sock
            mode: all

            # Or alternatively...
            # type: IP
            # address: 127.0.0.1
            # port: 4010

            requesttimeout: 5
        }

        scanprotocol {
            type: SSSP
            logrequests: YES

            # Options are: NO, FILE, DIR, SUBDIR
            allowscanfile: SUBDIR

            # Options are: NO, YES
            allowscandata: YES

            # Byte size of largest file to scan, or 0 for unlimited size.
            maxscandata: 1048576
        }

        scanner {
            type: SAVI
            inprocess: YES
            maxscantime: 3
            maxrequesttime: 10

            savigrp: GrpExecutable 1
            savigrp: GrpArchiveUnpack 1
            savigrp: GrpSelfExtract 1
            savigrp: GrpInternet 1
            savigrp: GrpMSOffice 1

            # For local-to-webserver use, list the PHP temporary upload directory
            # here. Beware that modern Linux distribution web servers may use
            # private temporary directories which make uploaded files inaccessible
            # to the scanner.
            allow: /var/tmp/php
        }
    }

