<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Strings for component 'antivirus_savdi', language 'en'.
 *
 * @package    antivirus_savdi
 * @copyright  2020 The University of Southern Queensland
 * @author     Jonathon Fowler <fowlerj@usq.edu.au>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

$string['chmodscanfile'] = 'Change scan file permissions';
$string['chmodscanfiledescr'] = 'Enable this option to have the permissions of the file being scanned temporarily changed to world-readable. Useful when the scanner daemon is local to the web server, but the file being scanned is not readable by the scanner process. Not necessary if the scanner daemon is remote.';
$string['conntcp'] = 'TCP/IP host:port';
$string['conntype'] = 'Connect to SAVDI daemon by';
$string['conntypedescr'] = 'If the SAVDI daemon is local to the web server and can read files created by the web server, ensure the daemon supports the \'SCANFILE\' request type and disable the *SAVDI daemon is remote* option.

If the SAVDI daemon is remote to the web server, or it is local but cannot read files created by web server, ensure that the daemon supports the \'SCANDATA\' request type and enable the *SAVDI daemon is remote* option.';
$string['conntypetcp'] = 'TCP/IP connection';
$string['conntypeunix'] = 'Unix domain socket';
$string['connunix'] = 'Path to Unix domain socket';
$string['daemonerroractlikevirus'] = 'Treat files as infected';
$string['daemonerrordonothing'] = 'Treat files as OK';
$string['errorcantopentcpsocket'] = 'Connecting to TCP socket resulted in error {$a}';
$string['errorcantopenunixsocket'] = 'Connecting to Unix domain socket resulted in error {$a}';
$string['errorfileopen'] = 'Error opening file {$a}';
$string['errorgeneral'] = 'SAVDI scanner said: {$a}';
$string['errorprotocol'] = 'SAVDI protocol error: {$a}';
$string['errorrejected'] = 'SAVDI server rejected the request: {$a}';
$string['errorsenddatashort'] = 'Data sent was shorter than expected';
$string['errorsenddatatoobig'] = 'Data size exceeds SAVDI server limit of {$a} bytes';
$string['errorservernotsupported'] = 'SAVDI server does not support request type {$a}';
$string['ondaemonerror'] = 'On scanner daemon error';
$string['ondaemonerrordescr'] = 'Action to assume when a connection or scanner error is encountered.';
$string['pluginname'] = 'Sophos SAVDI antivirus';
$string['privacy:metadata'] = 'The Sophos SAVDI antivirus plugin does not store any personal data.';
$string['scannerisremote'] = 'SAVDI daemon is remote';
$string['scannerisremotedescr'] = 'Enabling this option prevents direct reading of files by the SAVDI daemon, instead copying the data to be scanned to the daemon via network connection. The SAVDI daemon must support the \'SCANDATA\' request type and its \'maxscandata\' setting must be set large enough for the expected content.';
$string['warngeneral'] = 'SAVDI scanner said: {$a}';
$string['warnprotocol'] = 'SAVDI protocol warning: {$a}';
