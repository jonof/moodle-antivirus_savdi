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
 * @copyright  2017 The University of Southern Queensland
 * @author     Jonathon Fowler <fowlerj@usq.edu.au>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

$string['conntcp'] = 'TCP/IP host:port';
$string['conntype'] = 'Connect to SAVDI daemon by';
$string['conntypedescr'] = 'Whichever connection type you use, the SAVDI daemon must be local to your web server as uploaded files are not copied to a shared location for a remote daemon to access them.';
$string['conntypetcp'] = 'TCP/IP connection';
$string['conntypeunix'] = 'Unix domain socket';
$string['connunix'] = 'Path to Unix domain socket';
$string['daemonerroractlikevirus'] = 'Treat files as infected';
$string['daemonerrordonothing'] = 'Treat files as OK';
$string['errorcantopentcpsocket'] = 'Connecting to TCP socket resulted in error {$a}';
$string['errorcantopenunixsocket'] = 'Connecting to Unix domain socket resulted in error {$a}';
$string['errorgeneral'] = 'SAVDI scanner said: {$a}';
$string['errorprotocol'] = 'SAVDI protocol error: {$a}';
$string['ondaemonerror'] = 'On scanner daemon error';
$string['ondaemonerrordescr'] = 'Action to assume when a connection or scanner error is encountered.';
$string['pluginname'] = 'Sophos SAVDI antivirus';
$string['warngeneral'] = 'SAVDI scanner said: {$a}';
$string['warnprotocol'] = 'SAVDI protocol warning: {$a}';
