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
 * Sophos SAVDI connection test tool.
 *
 * @package    antivirus_savdi
 * @copyright  2020 The University of Southern Queensland
 * @author     Jonathon Fowler <fowlerj@usq.edu.au>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require(__DIR__.'/../../../config.php');
require_once($CFG->libdir.'/adminlib.php');

admin_externalpage_setup('antivirus_savdi_testclient');

echo $OUTPUT->header();
echo $OUTPUT->heading(get_string('testclient', 'antivirus_savdi'));

$config = get_config('antivirus_savdi');

$table = new html_table();
$table->data[] = [
    get_string('conntype', 'antivirus_savdi'),
    get_string('conntype' . $config->conntype, 'antivirus_savdi'),
];
$table->data[] = [
    get_string('conn' . $config->conntype, 'antivirus_savdi'),
    s($config->{'conn' . $config->conntype}),
];

try {
    $client = new antivirus_savdi\client();
    $client->connect($config->conntype, $config->{'conn' . $config->conntype});

    // Connection good.
    $labelcell = get_string('testclientresult', 'antivirus_savdi');
    $errorcell = get_string('ok');
    $errorrow = new html_table_row([$labelcell, $errorcell]);
    $errorrow->attributes = ['class' => 'table-success'];
    $table->data[] = $errorrow;

    // Quote back the scanner's capabilities.
    $scannercaps = $client->get_scanner_capabilities();
    foreach ($scannercaps as $capname => $capvalue) {
        switch ($capname) {
            case 'hasscanfile':
            case 'hasscandir':
            case 'hasscandirr':
            case 'hasscandata':
                $capvalue = get_string($capvalue ? 'yes' : 'no');
                break;
            case 'maxscandata':
                if ($capvalue == 0) {
                    $capvalue = get_string('unlimited');
                } else {
                    $capvalue = number_format($capvalue);
                }
                break;
            case 'version':
            default:
                break;  // No change.
        }
        $table->data[] = [
            get_string('testclient' . $capname, 'antivirus_savdi'),
            s($capvalue),
        ];
    }

    $client->disconnect();

} catch (moodle_exception $e) {
    // Connection error.
    $labelcell = get_string('testclientresult', 'antivirus_savdi');
    $errorcell = s($e->getMessage());
    $errorrow = new html_table_row([$labelcell, $errorcell]);
    $errorrow->attributes = ['class' => 'table-danger'];
    $table->data[] = $errorrow;
}

echo html_writer::table($table);

echo $OUTPUT->footer();
