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

use antivirus_savdi\client;

admin_externalpage_setup('antivirus_savdi_testclient');

echo $OUTPUT->header();
echo $OUTPUT->heading(get_string('testclient', 'antivirus_savdi'));

$config = get_config('antivirus_savdi');
$client = new client();

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

} catch (moodle_exception $e) {
    // Connection error.
    $labelcell = get_string('testclientresult', 'antivirus_savdi');
    $errorcell = s($e->getMessage());
    $errorrow = new html_table_row([$labelcell, $errorcell]);
    $errorrow->attributes = ['class' => 'table-danger'];
    $table->data[] = $errorrow;
}

echo html_writer::table($table);

if ($client->is_connected()) {
    echo html_writer::tag('p', get_string('testclientscantest', 'antivirus_savdi'));
    $formbody = html_writer::empty_tag('input', ['name' => 'testfile',
        'type' => 'file', 'class' => 'form-control-file']);
    $formbody .= html_writer::empty_tag('input', ['name' => 'sesskey',
        'type' => 'hidden', 'value' => sesskey()]);
    $formbody .= html_writer::empty_tag('input', ['type' => 'submit',
        'value' => get_string('testclientuploadandscan', 'antivirus_savdi'),
        'class' => 'btn btn-secondary']);
    echo html_writer::tag('form', html_writer::div($formbody, 'form-group'), ['method' => 'POST',
        'enctype' => 'multipart/form-data', 'action' => $PAGE->url->out(false)]);

    // Go direct to PHP for uploaded file details.
    if (($formdata = data_submitted()) && confirm_sesskey() && !empty($_FILES['testfile'])) {
        $table = new html_table();

        if ($_FILES['testfile']['error'] == 0 && is_uploaded_file($_FILES['testfile']['tmp_name'])) {
            $table->data[] = [
                get_string('testclientscantestpath', 'antivirus_savdi'),
                s($_FILES['testfile']['tmp_name'])
            ];

            $result = $client->scanfile($_FILES['testfile']['tmp_name']);
            $table->data[] = make_result_row('file', $result, $client);

            $result = $client->scandata(file_get_contents($_FILES['testfile']['tmp_name']));
            $table->data[] = make_result_row('data', $result, $client);
        } else {
            if ($_FILES['testfile']['error'] == 0) {
                $errstr = get_string('testclientscanuploaderrornotrecognised',
                    'antivirus_savdi', $_FILES['testfile']['tmp_name']);
            } else {
                $errstr = get_string('testclientscanuploaderror',
                    'antivirus_savdi', file_get_upload_error($_FILES['testfile']['error']));
            }
            $errorrow = new html_table_row([
                get_string('testclientscantestpath', 'antivirus_savdi'),
                $errstr
            ]);
            $errorrow->attributes = ['class' => 'table-danger'];
            $table->data[] = $errorrow;
        }

        echo html_writer::table($table);
    }
}

$client->disconnect();

echo $OUTPUT->footer();

/**
 * Generates a table row object for the test scan outcome display.
 *
 * @param string $type 'file' or 'data'.
 * @param integer $result the result code from the client scan call.
 * @param client $client the client object for further interrogation.
 * @return html_table_row
 */
function make_result_row($type, $result, $client) {
    $resultrow = new html_table_row([
        get_string('testclientscan' . $type . 'result', 'antivirus_savdi'),
        get_string('clientresult' . $result, 'antivirus_savdi')
    ]);
    $resultrow->attributes = ['class' => 'table-success'];

    if ($result == client::RESULT_VIRUS) {
        $viruslist = $client->get_scan_viruses();
        $resultrow->cells[1]->text .= html_writer::alist(
            array_map(
                function ($filename, $virusname) {
                    if ($filename !== '') {
                        return s($filename) . ' &ndash; ' . s($virusname);
                    }
                    return s($virusname);
                },
                array_keys($viruslist), $viruslist
            ),
            ['class' => 'list-unstyled']
        );
    } else if (client::is_error_result($result)) {
        $resultrow->cells[1]->text .= html_writer::div(
            get_string('errorgeneral', 'antivirus_savdi', $client->get_scan_message())
        );
        $resultrow->attributes = ['class' => 'table-danger'];
    }

    return $resultrow;
}
