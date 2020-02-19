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
 * Sophos SAVDI antivirus integration.
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
 * Class implemeting Sophos SAVDI antivirus.
 *
 * @copyright  2016 The University of Southern Queensland
 * @author     Jonathon Fowler <fowlerj@usq.edu.au>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class scanner extends \core\antivirus\scanner {
    /**
     * The protocol client instance.
     * @var antivirus_savdi\client
     */
    protected $client;

    /**
     * Destructor for an orderly disconnect.
     */
    public function __destruct() {
        if ($this->client) {
            $this->client->close();
        }
    }

    /**
     * Are the necessary antivirus settings configured?
     *
     * @return bool True if all necessary config settings been entered
     */
    public function is_configured() {
        $conntype = $this->get_config('conntype');
        if ($conntype === 'tcp' || $conntype === 'unix') {
            return !empty($this->get_config('conn' . $conntype));
        }
        return false;
    }

    /**
     * Fetch a connected client.
     *
     * @return client
     */
    protected function get_client() {
        if (!$this->client) {
            $conntype = $this->get_config('conntype');
            $connhost = $this->get_config('conn' . $conntype);
            $client = new client();
            $client->connect($conntype, $connhost);
            $this->client = $client;
        }
        return $this->client;
    }

    /**
     * Scan file, throws exception in case of infected file.
     *
     * @param string $file Full path to the file.
     * @param string $filename Name of the file (could be different from physical file if temp file is used).
     * @return int Scanning result constant.
     */
    public function scan_file($file, $filename) {
        if ($this->get_config('ondaemonerror') === 'donothing') {
            $onerrorreturn = self::SCAN_RESULT_OK;
        } else {
            $onerrorreturn = self::SCAN_RESULT_ERROR;
        }

        $origmode = fileperms($file);
        try {
            $client = $this->get_client();
            chmod($file, 0644);
            $scanresult = $client->scanfile($file);
        } catch (moodle_exception $e) {
            $this->message_admins($e->getMessage());
            return $onerrorreturn;
        } finally {
            chmod($file, $origmode);
        }

        if ($scanresult === client::RESULT_VIRUS) {
            return self::SCAN_RESULT_FOUND;
        } else if ($scanresult === client::RESULT_ERROR) {
            // An error of some kind. Proceed according to configuration.
            $this->message_admins($client->get_scan_message());
            return $onerrorreturn;
        }

        return self::SCAN_RESULT_OK;
    }
}
