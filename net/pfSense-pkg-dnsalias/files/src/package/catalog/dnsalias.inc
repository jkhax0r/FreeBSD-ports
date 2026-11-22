<?php
/* Native package callbacks only. No URL/request parameters or service actions.
 * Invoked by authenticated pfSense package management or its local CLI.
 * Configuration publication belongs to the pinned Python coordinator. */
const DNSALIAS_PACKAGE_CONFIG_LIBRARY_SHA256 = '9a34d3ddccd4d470db54730d0b99e60056f1c540af5fa725e656c224c27f6571';

function dnsalias_package_paths(): array {
    if (!function_exists('posix_geteuid') || posix_geteuid() !== 0 ||
        !function_exists('config_get_path') || !function_exists('config_read_file') ||
        !function_exists('parse_xml_config') || !function_exists('g_get') ||
        hash_file('sha256', '/etc/inc/config.lib.inc') !== DNSALIAS_PACKAGE_CONFIG_LIBRARY_SHA256) {
        throw new RuntimeException('DNS Alias requires its qualified native configuration API.');
    }
    $prefix = dirname(__DIR__);
    if (realpath($prefix) !== $prefix || !preg_match('~^/[A-Za-z0-9_./-]+$~D', $prefix)) {
        throw new RuntimeException('DNS Alias package prefix changed.');
    }
    $configuration = $prefix === '/usr/local' ? '/cf/conf/config.xml' : $prefix . '/etc/pfsense/config.xml';
    if (realpath(g_get('conf_path') . '/config.xml') !== $configuration) {
        throw new RuntimeException('DNS Alias package configuration target differs from native context.');
    }
    return [$prefix, $configuration, $prefix . '/share/dnsalias/bootstrap.py'];
}

function dnsalias_package_file(string $path, int $limit): string {
    clearstatcache(true, $path);$info = @lstat($path);
    if ($info === false || ($info['mode'] & 0170000) !== 0100000 || ($info['mode'] & 0777) !== 0600 ||
        $info['uid'] !== 0 || $info['nlink'] !== 1 || $info['size'] <= 0 || $info['size'] > $limit) {
        throw new RuntimeException('DNS Alias package file ownership changed.');
    }
    $raw = file_get_contents($path, false, null, 0, $limit + 1);
    clearstatcache(true, $path);$after = @lstat($path);
    $stable = is_array($after);
    foreach (['dev','ino','mode','nlink','uid','gid','size','mtime','ctime'] as $key) {
        if (!$stable || $after[$key] !== $info[$key]) { $stable = false;break; }
    }
    if (!is_string($raw) || strlen($raw) !== $info['size'] || !$stable) {
        throw new RuntimeException('DNS Alias package file changed during read.');
    }
    return $raw;
}

function dnsalias_package_tree(string $path): array {
    $raw = dnsalias_package_file($path, 2097152);
    if (preg_match('/<!\s*(?:DOCTYPE|ENTITY)\b/i', $raw)) {
        throw new RuntimeException('DNS Alias configuration structure rejected.');
    }
    $tree = parse_xml_config('data://text/plain;base64,' . base64_encode($raw), 'pfsense');
    if (!is_array($tree) || !$tree) { throw new RuntimeException('DNS Alias configuration read failed.'); }
    return $tree;
}

function dnsalias_package_run(string $action): array {
    if (!in_array($action, ['catalog-sync', 'catalog-resync', 'remove'], true)) {
        throw new RuntimeException('DNS Alias fixed package action required.');
    }
    [$prefix, $configuration, $helper] = dnsalias_package_paths();
    dnsalias_package_file($helper, 65536);
    if (config_get_path('') !== dnsalias_package_tree($configuration)) {
        throw new RuntimeException('DNS Alias package context has unsaved configuration changes.');
    }
    $process = proc_open(['/usr/local/bin/python3.11', '-B', $helper, $action, '--prefix', $prefix],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null,
        ['PATH' => '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin', 'LC_ALL' => 'C']);
    if (!is_resource($process)) { throw new RuntimeException('DNS Alias package helper did not launch.'); }
    fclose($pipes[0]);stream_set_blocking($pipes[1], false);stream_set_blocking($pipes[2], false);
    $stdout = '';$stderr = '';$failure = null;$exit = null;$deadline = hrtime(true) + 30000000000;
    try {
        while (true) {
            $stdout .= stream_get_contents($pipes[1], 32769 - min(32768, strlen($stdout)));
            $stderr .= stream_get_contents($pipes[2], 8193 - min(8192, strlen($stderr)));
            if (strlen($stdout) > 32768 || strlen($stderr) > 8192 || hrtime(true) >= $deadline) {
                $failure = 'DNS Alias package helper outcome requires inspection.';break;
            }
            $status = proc_get_status($process);
            if (!$status['running']) { $exit = $status['exitcode'];break; }
            usleep(10000);
        }
    } finally {
        if ($failure !== null) { proc_terminate($process); }
        $stdout .= stream_get_contents($pipes[1], 32769 - min(32768, strlen($stdout)));
        $stderr .= stream_get_contents($pipes[2], 8193 - min(8192, strlen($stderr)));
        fclose($pipes[1]);fclose($pipes[2]);$closed = proc_close($process);
        if ($exit === null && $closed >= 0) { $exit = $closed; }
        // The child may have published config before reporting failure. Never
        // let native package management write its stale pre-child snapshot.
        $fresh = dnsalias_package_tree($configuration);
        if (!config_read_file(false, false) || config_get_path('') !== $fresh) {
            throw new RuntimeException('DNS Alias native context refresh failed; stop package writes.');
        }
    }
    if ($failure !== null || $exit !== 0 || trim($stderr) !== '' || strlen($stdout) > 32768) {
        throw new RuntimeException('DNS Alias package operation incomplete; inspect installer receipts.');
    }
    try { $result = json_decode($stdout, true, 32, JSON_THROW_ON_ERROR); }
    catch (Throwable $error) { throw new RuntimeException('DNS Alias package completion uncertain; inspect receipts.'); }
    if (!is_array($result) || array_is_list($result)) { throw new RuntimeException('DNS Alias package completion schema changed.'); }
    return $result;
}

function dnsalias_package_install(): array { return dnsalias_package_run('catalog-sync'); }
function dnsalias_package_resync(): array { return dnsalias_package_run('catalog-resync'); }
function dnsalias_package_remove(): array { return dnsalias_package_run('remove'); }
