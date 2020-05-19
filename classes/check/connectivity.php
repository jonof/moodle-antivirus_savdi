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
 * Sophos SAVDI antivirus status check.
 *
 * @package    antivirus_savdi
 * @copyright  2020 The University of Southern Queensland
 * @author     Jonathon Fowler <fowlerj@usq.edu.au>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_savdi\check;

defined('MOODLE_INTERNAL') || die();

use core\check\result;
use antivirus_savdi\scanner;
use antivirus_savdi\client;

/**
 * SAVDI connectivity and communication check.
 *
 * @copyright  2020 The University of Southern Queensland
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class connectivity extends \core\check\check {
    /**
     * Return the result.
     *
     * @return result object
     */
    public function get_result(): result {
        $scanner = new scanner();
        if (!$scanner->is_configured()) {
            return new result(result::NA,
                get_string('checkconnectivitynoconfig', 'antivirus_savdi')
            );
        }

        // How severely to fail the check depends on configuration.
        if ($scanner->get_config('ondaemonerror') === 'donothing') {
            $errorresult = result::WARNING;
        } else {
            $errorresult = result::ERROR;
        }

        // Get a connected client object.
        try {
            $client = $scanner->get_client();
        } catch (\moodle_exception $e) {
            return new result($errorresult, $e->getMessage());
        }

        // Scanning 1 kilobyte of safe data should always succeed for the
        // scanner to be much use to anyone.
        $testdata = str_pad('', 1024, 'antivirus_savdi ');
        $scandataresult = null;
        $scanfileresult = null;

        // Check behaviour of scandata.
        try {
            $scandataresult = $client->scandata($testdata);
            switch ($scandataresult) {
                case client::RESULT_OK:
                case client::RESULT_ERROR_NOTSUPPORTED:
                    break;
                case client::RESULT_VIRUS:
                    return new result($errorresult,
                        get_string('checkconnectivityfalsepositive', 'antivirus_savdi')
                    );
                default:
                    return new result($errorresult,
                        get_string('checkconnectivityscandataerror', 'antivirus_savdi',
                            $client->get_scan_message())
                    );
            }
        } catch (\moodle_exception $e) {
            return new result($errorresult,
                get_string('checkconnectivityscandataerror', 'antivirus_savdi', $e->getMessage())
            );
        }

        // Check scanfile using a test file written where PHP would write uploaded file contents.
        $uploaddir = ini_get('upload_tmp_dir') ?? sys_get_temp_dir();
        $tmptestfile = tempnam($uploaddir, 'antivirus_savdi');
        if ($tmptestfile && file_put_contents($tmptestfile, $testdata) !== strlen($testdata)) {
            debugging(sprintf('temporary test file %s could not be written', $tmptestfile), DEBUG_DEVELOPER);
            unlink($tmptestfile);
            $tmptestfile = null;
        }
        if ($tmptestfile) {
            try {
                $scanfileresult = $client->scanfile($tmptestfile);
                switch ($scanfileresult) {
                    case client::RESULT_OK:
                    case client::RESULT_ERROR_NOTSUPPORTED:
                        break;
                    case client::RESULT_VIRUS:
                        return new result($errorresult,
                            get_string('checkconnectivityfalsepositive', 'antivirus_savdi')
                        );
                    default:
                        return new result($errorresult,
                            get_string('checkconnectivityscanfileerror', 'antivirus_savdi',
                                $client->get_scan_message())
                        );
                }
            } catch (\moodle_exception $e) {
                return new result($errorresult,
                    get_string('checkconnectivityscanfileerror', 'antivirus_savdi', $e->getMessage())
                );
            } finally {
                unlink($tmptestfile);
            }
        }

        // Interpret the results. Only OK and NOTSUPPORTED will have made it past the earlier tests.
        if ($scandataresult === client::RESULT_ERROR_NOTSUPPORTED &&
                $scanfileresult === client::RESULT_ERROR_NOTSUPPORTED) {
            return new result($errorresult, get_string('checkconnectivitynomethods', 'antivirus_savdi'));
        } else if ($scanfileresult === null) {
            // A potentially working though not fully exercised setup because file scanning was skipped.
            return new result(result::INFO, get_string('checkconnectivitytmpfileerror', 'antivirus_savdi'));
        } else {
            return new result(result::OK, get_string('checkconnectivityok', 'antivirus_savdi'));
        }
    }
}
