<?php
/**
 * Error 403 page for Mod Security - with false positive reporting to email and/or Slack webhook
 * User: peeter@zone.eu
 * Date: 2019-08-18
 * Time: 16:29
 *
 * Location of this script has to be set as Apache's Error 403 page,
 * with parameters 'email' and/or 'slack' providing endpoints for reporting:
 *   /waf-handler/index.php?email=monitoring@example.com&slack=https://hooks.slack.com/services/T12...3T/B12...3B/hU12...3Uh
 *
 *
 *
 */

ajax_handler();

function ajax_handler() {

	if ( ! empty( $_POST['id'] ) ) {

		$unique_id = $_POST['id'];

		if ( strlen( $unique_id ) >= 24
		     && strlen( $unique_id ) <= 27
		     && preg_match( '/^[A-Za-z0-9@-]+$/', $unique_id ) ) {

			$txt = parse_log( $unique_id );

			if ( ! empty( $txt ) && ! empty( $_SERVER['CGI_ERRORDOC_403'] ) ) {

				$uri = parse_url( $_SERVER['CGI_ERRORDOC_403'], PHP_URL_QUERY );

				parse_str( $uri, $params );

				if ( ! empty( $params['slack'] ) && preg_match( '/^[A-Za-z0-9:\/\.]+$/', $params['slack'] ) ) {
					slack_it( $params['slack'], $txt );
				}

				if ( ! empty( $params['email'] ) && filter_var( $params['email'], FILTER_VALIDATE_EMAIL ) ) {
					email_it( $params['email'], $txt );
				}
			}

			echo "OK";

		} else {
			echo "FAIL";
		}

		die();
	}
}

function error_log_path() {

	$logname   = $_SERVER['REQUEST_SCHEME'] === 'http' ? 'apache.error.log' : 'apache.ssl.error.log';
	$logfolder = 'logs';
	$hostroot  = implode( DIRECTORY_SEPARATOR, array_slice( explode( DIRECTORY_SEPARATOR, $_SERVER['DOCUMENT_ROOT'] ), 0, 5 ) );

	return implode( DIRECTORY_SEPARATOR, [ $hostroot, $logfolder, $logname ] );

}

function parse_log( $unique_id ) {

	$loglines = file_grep_contents( error_log_path(), "[unique_id \"{$unique_id}\"]" );

	$txt = '';

	if ( count( $loglines ) > 0 ) {

		$txt = '';

		$parts = [
			'date'    => '~^\[(.*?)\]~',
			'type'    => '~\] \[([a-z]*?)\] \[~',
			'client'  => '~\] \[client ([0-9\.]*)\]~',
			'message' => '~\] ModSecurity: (.*?) \[~',
			'msg'     => '~\] \[msg ([^\]]*)~',
			'data'    => '~\] \[data ([^\]]*)~',
			'file'    => '~\[file ([^\]]*)~',
			'line'    => '~\] \[line ([^\]]*)~',
			'id'      => '~\] \[id ([^\]]*)~',
			'uri'     => '~\] \[uri ([^\]]*)~',
		];

		foreach ( $loglines as $logline ) {

			$parsed = [];

			foreach ( $parts as $name => $pattern ) {

				$mathces = [];

				preg_match( $pattern, $logline, $mathces );

				if ( ! empty( $mathces[1] ) ) {
					$parsed[ $name ] = trim( $mathces[1], '"' );

					if ( $name === 'file' ) {
						$parsed[ $name ] = basename( $parsed[ $name ], '.conf' );
					}

				} else {
					$parsed[ $name ] = '';
				}
			}

			if ( empty( $parsed['date'] ) ) {
				continue;
			}

			if ( empty( $txt ) ) {
				$txt = "*FALSE POSITIVE REPORTED* by {$parsed['client']}\nID: {$unique_id}\n";
			}

			if ( ! empty( $parsed['data'] ) ) {
				$txt .= "```#{$parsed['id']} {$parsed['msg']} ({$parsed['data']}) {$parsed['file']}:{$parsed['line']}```\n";
			} else {
				$txt .= "*{$parsed['msg']}* `#{$parsed['id']}`\n";
			}

		}
	}

	return $txt;
}

function file_grep_contents( $filename, $searchstring ) {

	$matches = [];

	if ( is_readable( $filename ) ) {

		$fh = fopen( $filename, "r" );

		while ( ! feof( $fh ) ) {
			$buffer = fgets( $fh );
			if ( strpos( $buffer, $searchstring ) !== false ) {
				$matches[] = $buffer;
			}
		}
		fclose( $fh );

	}

	return $matches;
}

function slack_it( $webhook, $message ) {

	$payload = array( 'text' => $message, 'username' => $_SERVER['SERVER_NAME'] );

	$ch = curl_init( $webhook );
	curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
	curl_setopt( $ch, CURLOPT_POST, true );
	curl_setopt( $ch, CURLOPT_POSTFIELDS, [ 'payload' => json_encode( $payload ) ] );
	$response = curl_exec( $ch );
	curl_close( $ch );

	return $response;

}

function email_it( $to, $txt ) {

	$subject = '[ModSecurity] False positive triggered';
	$headers = 'From: modsecurity@' . $_SERVER['SERVER_NAME'] . "\r\n" .
	           'X-Mailer: ModSecurity Error 403 handler';

	mail( $to, $subject, $txt, $headers );

}

// Show the error page

header( $_SERVER['SERVER_PROTOCOL'] . " 403 Forbidden" );
header( "Status: 403 Forbidden" );
header( "Connection: close" );

?><!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="referrer" content="no-referrer" >
    <meta name="robots" content="noindex,nofollow" >

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
          integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">

    <title>Request blocked by WAF</title>
</head>
<body>
<div class="container">
    <div class="row">
        <div class="col-12">
            <h1>Request blocked</h1>
            <p>Something has triggered the web application firewall (WAF) - most probably a form field in search or
                website admin. Unless you were performing security tests this is a false postive. This incident has been
                reported to webmaster.</p>
            <pre><?= $_SERVER["UNIQUE_ID"] ?></pre>
        </div>
    </div>
</div>

<script>

    var xhr = new XMLHttpRequest();

    xhr.open('POST', '/waf-handler/');
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.setRequestHeader('referrer', 'test');
    xhr.send(encodeURI('id=<?= $_SERVER["UNIQUE_ID"] ?>'));

</script>
</body>
</html>