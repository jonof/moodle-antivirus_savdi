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
 * Sophos SAVDI antivirus protocol client.
 *
 * @package    antivirus_savdi
 * @copyright  2017 The University of Southern Queensland
 * @author     Jonathon Fowler <fowlerj@usq.edu.au>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_savdi;

defined('MOODLE_INTERNAL') || die();

use moodle_exception;

/**
 * SAVDI protocol client implementation.
 *
 * See https://www.sophos.com/en-us/medialibrary/PDFs/documentation/savi_sssp_13_meng.pdf
 * for the specification.
 */
class client {
    private $socket;

    public $debugprotocol = false;

    private $viruses = [];
    private $errormsg;

    const RESULT_OK = 0;
    const RESULT_VIRUS = 1;
    const RESULT_ERROR = 2;

    /**
     * Establish a connection to the SAVDI daemon or die trying.
     * @param string $type 'unix' or 'tcp'
     * @param string $host path to unix socket, or tcp host:port
     * @return void
     * @throws moodle_exception
     */
    public function connect($type, $host) {
        $this->close();

        $this->socket = stream_socket_client($type . '://' . $host, $errno, $errstr, 5);
        if (!$this->socket) {
            throw new moodle_exception('errorcantopen'.$type.'socket', 'antivirus_savdi', '', "$errstr ($errno)");
        }

        // Expect the server to greet us.
        if ($this->getmessage() !== "OK SSSP/1.0") {
            fclose($this->socket);
            $this->socket = null;
            throw new moodle_exception('errorprotocol', 'antivirus_savdi', '', 'bad server greeting');
        }
        $this->sendmessage("SSSP/1.0");
        if (strpos($this->getmessage(), "ACC ") !== 0) {
            fclose($this->socket);
            $this->socket = null;
            throw new moodle_exception('errorprotocol', 'antivirus_savdi', '', 'bad protocol version handshake');
        }
    }

    /**
     * Disconnect from the SAVDI daemon in a clean manner.
     */
    public function close() {
        if (!$this->socket) {
            return;
        }

        // Disconnect cleanly.
        $this->sendmessage("BYE");
        if ($this->getmessage() !== "BYE" && $this->debugprotocol) {
            debugging(get_string('warnprotocol', 'antivirus_savdi', 'did not receive expected signoff'), DEBUG_DEVELOPER);
        }

        fclose($this->socket);
        $this->socket = null;
    }

    /**
     * Scan a file.
     * @param string $filename
     * @return integer RESULT_* codes
     */
    public function scanfile($filename) {
        return $this->scan('SCANFILE', $filename);
    }

    /**
     * Scan a directory.
     * @param string $dirname
     * @param boolean $recurse
     * @return integer RESULT_* codes
     */
    public function scandir($dirname, $recurse = false) {
        if ($recurse) {
            $verb = 'SCANDIRR';
        } else {
            $verb = 'SCANDIR';
        }
        return $this->scan($verb, $dirname);
    }

    /**
     * Scan files and directories.
     * @param string $cmd SCANFILE, SCANDIR, SCANDIRR
     * @param string $path
     * @return integer RESULT_* codes
     */
    private function scan($cmd, $path) {
        $scanresult = self::RESULT_ERROR;
        $expectnewline = false;
        $this->viruses = [];
        $this->errormsg = null;

        $this->sendmessage("$cmd " . urlencode($path));
        while (true) {
            $msg = $this->getmessage();
            if ($msg === null) {
                break;  // EOF
            } else if ($msg === "") {
                if ($expectnewline) {
                    break;  // Newline after a 'DONE'.
                }
                continue;
            }
            list($response, $extra) = explode(' ', $msg, 2);
            switch ($response) {
                case 'ACC':     // Daemon accepted the request.
                    continue;
                case 'REJ':     // Daemon rejected the request.
                    break 2;
                case 'EVENT':   // Progress reporting.
                case 'TYPE':
                case 'FILE':
                    continue;
                case 'OK':      // Outcome reporting.
                case 'FAIL':
                    continue;
                case 'VIRUS':   // Virus identified.
                    list ($virus, $filename) = explode(' ', $extra, 2);
                    $this->viruses[$filename] = $virus;
                    debugging('found virus ' . $virus . ' in ' . $filename, DEBUG_NORMAL);
                    continue;
                case 'DONE':
                    list ($result, $code, $codemsg) = explode(' ', $extra, 3);
                    if ($result === 'OK') {
                        if ($code === '0000') {
                            $scanresult = self::RESULT_OK;      // No virus.
                        } else if ($code === '0203') {
                            $scanresult = self::RESULT_VIRUS;   // Virus found.
                        } else {
                            debugging(get_string('warngeneral', 'antivirus_savdi', "OK - $codemsg ($code)"), DEBUG_NORMAL);
                        }
                    } else {
                        debugging(get_string('errorgeneral', 'antivirus_savdi', "FAIL - $codemsg ($code)"), DEBUG_NORMAL);
                    }
                    $this->errormsg = "$code $codemsg";
                    $expectnewline = true;
                    continue;
                default:
                    if ($this->debugprotocol) {
                        debugging(get_string('errorprotocol', 'antivirus_savdi',
                            "wasn't expecting: " . addcslashes($msg, "\0..\37!@\177..\377")), DEBUG_DEVELOPER);
                    }
                    break;
            }
        }

        return $scanresult;
    }

    /**
     * Read a message from the server.
     * @return string|null message string, or null on error or eof
     */
    private function getmessage() {
        $msg = fgets($this->socket);
        if ($msg === false) {
            // Error or EOF.
            if ($this->debugprotocol) {
                debugging('SAVDI > (EOF)', DEBUG_DEVELOPER);
            }
            return null;
        }
        $msg = rtrim($msg, "\r\n");
        if ($this->debugprotocol) {
            debugging('SAVDI > '.$msg, DEBUG_DEVELOPER);
        }
        return $msg;
    }

    /**
     * Write a message to the server.
     * @param string $msg
     * @return void
     */
    private function sendmessage($msg) {
        if ($this->debugprotocol) {
            debugging('SAVDI < '.$msg, DEBUG_DEVELOPER);
        }
        fwrite($this->socket, $msg . "\r\n");
        fflush($this->socket);
    }

    /**
     * Return the list of discovered viruses from the last scan.
     * @return array(filename => virusname)
     */
    public function get_scan_viruses() {
        return $this->viruses;
    }

    /**
     * Return the scanner response from the last scan.
     * @return string
     */
    public function get_scan_message() {
        return $this->errormsg;
    }
}
