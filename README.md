# Sophos SAVDI antivirus plugin for Moodle 3.2+

Copyright © 2017 The University of Southern Queensland (https://www.usq.edu.au)

This plugin adds virus scanner support for the Sophos SAVDI daemon to Moodle 3.2 and newer. Note that the *savdid* daemon must run on the same host as the Moodle instance. Communication with the daemon may be via TCP/IP or Unix domain socket.

The Sophos Simple Scanning Protocol is documented at https://www.sophos.com/en-us/medialibrary/PDFs/documentation/savi_sssp_13_meng.pdf

An example *savdid* configuration (see https://www.sophos.com/en-us/medialibrary/PDFs/documentation/SAVDI_User_Manual.pdf for full documentation):

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

            # type: IP
            # address: 127.0.0.1
            # port: 4010

            requesttimeout: 5
        }

        scanprotocol {
            type: SSSP
            allowscanfile: SUBDIR
            allowscandata: NO
            logrequests: YES
        }

        scanner {
            type: SAVI
            inprocess: YES
            maxscantime: 3
            maxrequesttime: 10
            allow: /var/tmp/php
            savigrp: GrpExecutable 1
            savigrp: GrpArchiveUnpack 1
            savigrp: GrpSelfExtract 1
            savigrp: GrpInternet 1
            savigrp: GrpMSOffice 1
        }
    }

