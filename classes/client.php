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
 * @copyright  2020 The University of Southern Queensland
 * @author     Jonathon Fowler <fowlerj@usq.edu.au>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_savdi;

use moodle_exception;

/**
 * SAVDI protocol client implementation.
 *
 * See https://www.sophos.com/en-us/medialibrary/PDFs/documentation/savi_sssp_13_meng.pdf
 * for the specification.
 *
 * @copyright  2020 The University of Southern Queensland
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class client {
    /**
     * The TCP/Unix socket.
     * @var resource
     */
    protected $socket;

    /**
     * Whether to emit the SAVDI conversation as debug output.
     * @var bool
     */
    public $debugprotocol = false;

    /**
     * Discovered viruses in the most recent scan.
     * @var array filename => virus name
     */
    private $viruses = [];

    /**
     * The most recent scanner daemon result message from the most recent scan.
     * @var string
     */
    private $resultmsg;

    /**
     * The most recent scanner daemon result code from the most recent scan.
     * @var string
     */
    private $resultcode;

    /**
     * A good scan result.
     * @var int
     */
    const RESULT_OK = 0;

    /**
     * A virus was found result.
     * @var int
     */
    const RESULT_VIRUS = 1;

    /**
     * A scan failure result.
     * @var int
     */
    const RESULT_ERROR = 2;

    /**
     * A request not supported failure result.
     * @var int
     */
    const RESULT_ERROR_NOTSUPPORTED = 3;

    /**
     * A data too large failure result.
     * @var int
     */
    const RESULT_ERROR_TOOLARGE = 4;


    /**
     * Whether the server supports the SCANFILE request.
     * @var bool
     */
    private $hasscanfile = false;

    /**
     * Whether the server supports the SCANDIR request.
     * @var bool
     */
    private $hasscandir  = false;

    /**
     * Whether the server supports the SCANDIRR request.
     * @var bool
     */
    private $hasscandirr = false;

    /**
     * Whether the server supports the SCANDATA request.
     * @var bool
     */
    private $hasscandata = false;

    /**
     * The maximum size of data accepted by SCANDATA. 0 means unlimited.
     * @var int
     */
    private $maxscandata = 0;

    /**
     * The scanner version string.
     * @var string
     */
    private $version;


    /**
     * The function call succeeded.
     * @var string
     */
    const SAVI_OK = '0000';

    /**
     * A virus was found during a virus scan.
     * @var string
     */
    const SAVI_ERROR_VIRUSPRESENT = '0203';

    /**
     * Scan terminated due to timeout.
     * @var string
     */
    const SAVI_ERROR_SCANTIMEOUT = '060F';

    /**
     * Human-readable SSSP reject codes.
     * @var array
     */
    const SAVI_REJ_MESSAGES = [
        1 => 'The request was not recognised',
        2 => 'The SSSP version number was incorrect',
        3 => 'There was an error in the OPTIONS list',
        4 => 'SCANDATA was trying to send too much data',
        5 => 'The request is not permitted',
    ];


    /**
     * Determine if a result code is an error.
     *
     * @param integer $result
     * @return boolean
     */
    public static function is_error_result($result) {
        return $result >= self::RESULT_ERROR;
    }


    /**
     * Establish a connection to the SAVDI daemon or die trying.
     *
     * @param string $type 'unix' or 'tcp'
     * @param string $host path to unix socket, or tcp host:port
     * @param int $tries the number of connections to attempt before failing.
     * @return void
     * @throws moodle_exception
     */
    public function connect($type, $host, $tries = 0) {
        $this->disconnect();

        $connected = false;
        $count = 0;
        while (!$connected) {
            $connected = true;
            try {
                if (!$this->open_socket($type . '://' . $host, $errno, $errstr)) {
                    throw new moodle_exception('errorcantopen'.$type.'socket', 'antivirus_savdi', '', "$errstr ($errno)");
                }

                // Expect the server to greet us.
                if ($this->getmessage() !== "OK SSSP/1.0") {
                    $this->close_socket();
                    throw new moodle_exception('errorprotocol', 'antivirus_savdi', '', 'bad server greeting');
                }
                $this->sendmessage("SSSP/1.0");
                if (strpos($this->getmessage(), "ACC ") !== 0) {
                    $this->close_socket();
                    throw new moodle_exception('errorprotocol', 'antivirus_savdi', '', 'bad protocol version handshake');
                }

                if (!$this->query_server_capabilities()) {
                    throw new moodle_exception('errorprotocol', 'antivirus_savdi', '', 'problem querying capabilities');
                }
            } catch (moodle_exception $e) {
                // If we still have tries left, increment count and redo.
                if ($count < $tries && $tries > 0) {
                    $count++;
                    $connected = false;
                } else {
                    // Reached max tries with an exception. Rethrow it.
                    throw $e;
                }
            }
        }
    }

    /**
     * Open the communication socket.
     *
     * @param string $sockpath
     * @param integer $errno receives an error code
     * @param string $errstr receives an error description
     * @return resource
     */
    protected function open_socket($sockpath, &$errno, &$errstr) {
        $this->socket = stream_socket_client($sockpath, $errno, $errstr, 5);
        return $this->socket !== false;
    }

    /**
     * Disconnect from the SAVDI daemon in a clean manner.
     *
     * @return void
     */
    public function disconnect() {
        if (!$this->is_connected()) {
            return;
        }

        // Disconnect cleanly.
        $this->sendmessage("BYE");
        if ($this->getmessage() !== "BYE" && $this->debugprotocol) {
            debugging(get_string('warnprotocol', 'antivirus_savdi', 'did not receive expected signoff'), DEBUG_DEVELOPER);
        }

        $this->close_socket();
    }

    /**
     * Closes the communication socket.
     *
     * @return void
     */
    protected function close_socket() {
        fclose($this->socket);
        $this->socket = null;
    }

    /**
     * Check if connected.
     *
     * @return boolean
     */
    public function is_connected() {
        return $this->socket !== null && $this->socket !== false;
    }

    /**
     * Scan a file on the scanner daemon's filesystem.
     *
     * @param string $filename
     * @return integer RESULT_* codes
     */
    public function scanfile($filename) {
        return $this->scanlocal('SCANFILE', $filename);
    }

    /**
     * Scan a directory on the scanner daemon's filesystem.
     *
     * @param string $dirname
     * @param boolean $recursivescan
     * @return integer RESULT_* codes
     */
    public function scandir($dirname, $recursivescan = false) {
        if ($recursivescan) {
            $requesttype = 'SCANDIRR';
        } else {
            $requesttype = 'SCANDIR';
        }
        return $this->scanlocal($requesttype, $dirname);
    }

    /**
     * Scan files or directories on the scanner daemon's filesystem.
     *
     * @param string $requesttype
     * @param string $path
     * @return integer RESULT_* codes
     */
    private function scanlocal($requesttype, $path) {
        if (!$this->{'has' . strtolower($requesttype)}) {
            $this->resultmsg = get_string('errorservernotsupported', 'antivirus_savdi', $requesttype);
            return self::RESULT_ERROR_NOTSUPPORTED;
        }
        $this->sendmessage($requesttype . ' ' . urlencode($path));
        return $this->handle_scan_response();
    }

    /**
     * Scan data.
     *
     * @param string $data
     * @return integer RESULT_* codes
     */
    public function scandata($data) {
        $size = strlen($data);
        if (!$this->hasscandata) {
            $this->resultmsg = get_string('errorservernotsupported', 'antivirus_savdi', 'SCANDATA');
            return self::RESULT_ERROR_NOTSUPPORTED;
        }
        if ($this->maxscandata > 0 && $size > $this->maxscandata) {
            $this->resultmsg = get_string('errorsenddatatoobig', 'antivirus_savdi', $this->maxscandata);
            return self::RESULT_ERROR_TOOLARGE;
        }

        $this->sendmessage('SCANDATA ' . $size);
        if (!$this->senddata($data, $size)) {
            $this->resultmsg = get_string('errorsenddatashort', 'antivirus_savdi');
            return self::RESULT_ERROR;
        }
        return $this->handle_scan_response();
    }

    /**
     * Scan data from an open file handle.
     *
     * @param resource $fileh
     * @return integer RESULT_* codes
     */
    public function scandatafileh($fileh) {
        $stat = fstat($fileh);
        $size = $stat['size'];
        if (!$this->hasscandata) {
            $this->resultmsg = get_string('errorservernotsupported', 'antivirus_savdi', 'SCANDATA');
            return self::RESULT_ERROR_NOTSUPPORTED;
        }
        if ($this->maxscandata > 0 && $size > $this->maxscandata) {
            $this->resultmsg = get_string('errorsenddatatoobig', 'antivirus_savdi', $this->maxscandata);
            return self::RESULT_ERROR_TOOLARGE;
        }

        $this->sendmessage('SCANDATA ' . $size);
        if (!$this->senddatastream($fileh, $size)) {
            $this->resultmsg = get_string('errorsenddatashort', 'antivirus_savdi');
            return self::RESULT_ERROR;
        }
        return $this->handle_scan_response();
    }

    /**
     * Process the response to a scan request.
     *
     * @return integer RESULT_* codes
     */
    private function handle_scan_response() {
        $scanresult = self::RESULT_ERROR;
        $expectnewline = false;
        $this->viruses = [];
        $this->resultmsg = null;

        while (true) {
            $msg = $this->getmessage();
            if ($msg === null) {
                break;  // EOF.
            } else if ($msg === "") {
                if ($expectnewline) {
                    break;  // Newline after a 'DONE'.
                }
                continue;
            }

            list($response, $extra) = explode(' ', $msg, 2);
            switch ($response) {
                case 'ACC':     // Daemon accepted the request.
                    break;
                case 'REJ':     // Daemon rejected the request.
                    $this->resultcode = (int)$extra;
                    $this->resultmsg = self::SAVI_REJ_MESSAGES[$extra];
                    debugging(get_string('errorrejected', 'antivirus_savdi', $this->resultmsg), DEBUG_NORMAL);
                    break 2;    // Break the while.

                case 'EVENT':   // Progress reporting.
                case 'TYPE':
                case 'FILE':
                    break;

                case 'OK':      // Outcome reporting.
                case 'FAIL':
                    break;

                case 'VIRUS':   // Virus identified.
                    list ($virus, $filename) = explode(' ', $extra, 2);
                    $filename = urldecode($filename);
                    $this->viruses[$filename] = $virus;
                    debugging('found virus ' . $virus . ' in ' . $filename, DEBUG_NORMAL);
                    break;

                case 'DONE':
                    list ($result, $code, $codemsg) = explode(' ', $extra, 3);
                    if ($result === 'OK') {
                        if ($code === self::SAVI_OK) {
                            $scanresult = self::RESULT_OK;      // No virus.
                        } else if ($code === self::SAVI_ERROR_VIRUSPRESENT) {
                            $scanresult = self::RESULT_VIRUS;   // Virus found.
                        } else {
                            debugging(get_string('warngeneral', 'antivirus_savdi', "OK - $codemsg ($code)"), DEBUG_NORMAL);
                        }
                    } else {
                        debugging(get_string('errorgeneral', 'antivirus_savdi', "FAIL - $codemsg ($code)"), DEBUG_NORMAL);
                    }
                    $this->resultcode = $code;
                    $this->resultmsg = $codemsg;
                    $expectnewline = true;
                    break;

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
     * Interrogate the server for its capabilities.
     *
     * @return boolean true if successful
     */
    private function query_server_capabilities() {
        $this->sendmessage("QUERY SERVER");

        while (true) {
            $msg = $this->getmessage();
            if ($msg === null) {
                break;  // EOF.
            } else if ($msg === "") {
                return true;
            }

            list($response, $extra) = explode(' ', $msg, 2);
            switch ($response) {
                case 'ACC':         // Daemon accepted the request.
                    break;
                case 'REJ':         // Daemon rejected the request.
                    $this->resultcode = (int)$extra;
                    $this->resultmsg = self::SAVI_REJ_MESSAGES[$extra];
                    debugging(get_string('errorrejected', 'antivirus_savdi', $this->resultmsg), DEBUG_NORMAL);
                    break 2;        // Break the while.

                case 'version:':    // The scanner's version string.
                    $this->version = $extra;
                    break;

                case 'method:':     // A supported request type.
                    switch ($extra) {
                        case 'SCANFILE':
                            $this->hasscanfile = true;
                            break;
                        case 'SCANDIR':
                            $this->hasscandir  = true;
                            break;
                        case 'SCANDIRR':
                            $this->hasscandirr = true;
                            break;
                        case 'SCANDATA':
                            $this->hasscandata = true;
                            break;
                    }
                    break;

                case 'maxscandata:':    // The maximum number of bytes for SCANDATA.
                    $this->maxscandata = intval($extra);
                    break;
            }
        }

        return false;
    }

    /**
     * Read a message from the server.
     *
     * @return string|null message string, or null on error or eof
     */
    protected function getmessage() {
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
     *
     * @param string $msg
     * @return void
     */
    protected function sendmessage($msg) {
        if ($this->debugprotocol) {
            debugging('SAVDI < '.$msg, DEBUG_DEVELOPER);
        }
        fwrite($this->socket, $msg . "\r\n");
        fflush($this->socket);
    }

    /**
     * Write raw data to the server.
     *
     * @param string $data
     * @param integer $bytes
     * @return boolean true if the expected number of bytes were sent
     */
    protected function senddata($data, $bytes) {
        if ($this->debugprotocol) {
            debugging('SAVDI < (' . $bytes . ' bytes...)', DEBUG_DEVELOPER);
        }

        $firstzerowrite = null;
        $sockettimeout = ini_get('default_socket_timeout'); // Note: can be <0 meaning 'forever'.

        $sent = 0;
        do {
            $tosend = min(8192, $bytes - $sent); // 8KB per fwrite call.
            $part = fwrite($this->socket, substr($data, $sent, $tosend));

            if ($part === false) {
                debugging('socket write returned error', DEBUG_DEVELOPER);
                break;
            } else if ($part === 0) {
                if ($firstzerowrite === null) {
                    $firstzerowrite = microtime(true);
                } else if (microtime(true) - $firstzerowrite >= $sockettimeout) {
                    debugging('timeout retrying on zero-byte writes', DEBUG_DEVELOPER);
                    break;
                }
                sleep(1);
                continue;
            } else if ($part < $tosend) {
                debugging(sprintf('socket write returned early after %d of %d bytes; resuming',
                    $part, $tosend), DEBUG_DEVELOPER);
            }

            $sent += $part;
            $firstzerowrite = null;
        } while ($sent < $bytes);

        fflush($this->socket);

        return $sent === $bytes;
    }

    /**
     * Write data from a resource to the server.
     *
     * @param resource $fileh
     * @param integer $bytes
     * @return boolean true if the expected number of bytes were sent
     */
    protected function senddatastream($fileh, $bytes) {
        if ($this->debugprotocol) {
            debugging('SAVDI < (' . $bytes . ' bytes from stream...)', DEBUG_DEVELOPER);
        }

        $sent = 0;
        do {
            $tosend = $bytes - $sent;
            $part = stream_copy_to_stream($fileh, $this->socket, $tosend);
            if ($part === false) {
                debugging('stream copy returned error', DEBUG_DEVELOPER);
                break;
            } else if ($part < $tosend) {
                debugging(sprintf('stream copy returned early after %d of %d bytes; resuming',
                    $part, $tosend), DEBUG_DEVELOPER);
            }
            $sent += $part;
        } while ($sent < $bytes && !feof($fileh));

        fflush($this->socket);

        return $sent === $bytes;
    }

    /**
     * Return the list of discovered viruses from the last scan.
     *
     * @return array filename => virus name
     */
    public function get_scan_viruses() {
        return $this->viruses;
    }

    /**
     * Return the scanner code from the last scan.
     *
     * @return string
     */
    public function get_scan_code() {
        return $this->resultcode;
    }

    /**
     * Return the scanner response from the last scan.
     *
     * @return string
     */
    public function get_scan_message() {
        return $this->resultmsg;
    }

    /**
     * Return the scanner daemon's queried capabilities.
     *
     * @return array
     */
    public function get_scanner_capabilities() {
        return [
            'version' => $this->version,
            'hasscanfile' => $this->hasscanfile,
            'hasscandir' => $this->hasscandir,
            'hasscandirr' => $this->hasscandirr,
            'hasscandata' => $this->hasscandata,
            'maxscandata' => $this->maxscandata,
        ];
    }
}
