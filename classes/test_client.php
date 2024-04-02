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
 * Sophos SAVDI antivirus protocol test client.
 *
 * @package    antivirus_savdi
 * @copyright  2020 The University of Southern Queensland
 * @author     Jonathon Fowler <fowlerj@usq.edu.au>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_savdi;

/**
 * Sophos SAVDI antivirus protocol test client.
 *
 * Protocol conversation scripts: these record expected back-and-forward
 * exchanges between a client and the SSSP server. Lines are preceded
 * by a character indicating the direction of message, or type of message.
 *
 * <...  server-to-client message, trailing ~ preserves preceding whitespace
 * >...  client-to-server message, trailing ~ preserves preceding whitespace
 * &nnn  client-to-server byte payload, nnn = count to expect
 *
 * @copyright  2020 The University of Southern Queensland
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class test_client extends \antivirus_savdi\client {
    /**
     * Handle of the open protocol conversation script.
     * @var resource
     */
    private $scriptfh;

    /**
     * The number of times to pretend to fail an open_socket() call.
     * @var int
     */
    public $opensocketfails = 0;

    /**
     * Constructor.
     */
    public function __construct() {
        $this->debugprotocol = false;
    }

    /**
     * Establish a fake connection that processes a recorded SSSP conversation.
     *
     * @param string $sockpath a file:// url referring to the conversation script.
     * @param integer $errno
     * @param string $errstr
     */
    protected function open_socket($sockpath, &$errno, &$errstr) {
        if ($this->opensocketfails > 0) {
            $this->opensocketfails--;
            $errno = 50;    // ENETDOWN.
            $errstr = 'Network is down';
            $this->socket = false;
            return false;
        }

        // Use an in-memory stream to simulate the read buffer.
        $this->socket = fopen('php://memory', 'w+b');
        if (!$this->socket) {
            throw new \coding_exception('error opening memory-backed file');
        }

        // Open the SSSP conversation script.
        list($type, $file) = explode('://', $sockpath, 2);
        if ($type !== 'file') {
            throw new \coding_exception('sockpath is not a file:// url');
        } else {
            $this->scriptfh = fopen($file, 'rb');
            if (!$this->scriptfh) {
                throw new \coding_exception("error opening test script $file");
            }
        }

        return true;
    }

    /**
     * Close the fake connection and conversation script.
     */
    protected function close_socket() {
        fclose($this->scriptfh);
        $this->scriptfh = null;

        parent::close_socket();
    }

    /**
     * Simulate getting a message from a socket by instead reading it from the script.
     *
     * @return string
     */
    protected function getmessage() {
        $line = fgets($this->scriptfh);
        if ($line === false) {
            throw new \coding_exception('unexpected eof from script file');
        } else if ($line[0] !== '<') {
            throw new \coding_exception('expected input from script file, got: ' . $line);
        }

        $line = rtrim($line, "\r\n");   // Normalise the line ending.
        if (substr($line, -2) === ' ~') {
            // Trailing whitespace is retained by placing a ~ at the end.
            $line = substr($line, 0, -1);
        }

        // Empty the in-memory stream and write into it what the parent will read.
        ftruncate($this->socket, 0);
        rewind($this->socket);
        fwrite($this->socket, substr($line, 1) . "\r\n");
        rewind($this->socket);

        return parent::getmessage();
    }

    /**
     * Simulate sending a message to a socket by reading what's expected from the script and comparing.
     *
     * @param string $msg
     * @return string
     */
    protected function sendmessage($msg) {
        $line = fgets($this->scriptfh);
        if ($line === false) {
            throw new \coding_exception('unexpected eof from script file');
        } else if ($line[0] !== '>') {
            throw new \coding_exception('expected output from script file, got: ' . $line);
        }

        $line = rtrim($line, "\r\n");   // Normalise the line ending.
        if ($msg !== substr($line, 1)) {
            throw new \coding_exception('message does not match the script');
        }
    }

    /**
     * Simulate sending a blob of data to a socket by comparing to the count expected in the script.
     *
     * @param string $data
     * @param integer $bytes
     * @return boolean
     */
    protected function senddata($data, $bytes) {
        $line = fgets($this->scriptfh);
        if ($line === false) {
            throw new \coding_exception('unexpected eof from script file');
        } else if ($line[0] !== '&') {
            throw new \coding_exception('expected a bytes count from script file, got: ' . $line);
        }

        $expect = (int)substr($line, 1);
        if ($bytes !== $expect) {
            throw new \coding_exception('byte count does not match the script');
        }
        return true;
    }

    /**
     * Simulate sending a blob of data read from an open stream to a socket by comparing to the
     * count expected in the script.
     *
     * @param resource $fileh
     * @param integer $bytes
     * @return boolean
     */
    protected function senddatastream($fileh, $bytes) {
        $line = fgets($this->scriptfh);
        if ($line === false) {
            throw new \coding_exception('unexpected eof from script file');
        } else if ($line[0] !== '&') {
            throw new \coding_exception('expected a bytes count from script file, got: ' . $line);
        }

        $expect = (int)substr($line, 1);
        if ($bytes !== $expect) {
            throw new \coding_exception('byte count does not match the script');
        }
        fseek($fileh, $bytes, SEEK_CUR);    // Pretend to have read.
        return true;
    }
}
