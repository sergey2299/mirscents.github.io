<?php
/**
 * MIR SCENTS — приём заказов из Telegram Mini App.
 *
 * Один файл, кладётся рядом с mir-scents.html на обычный хостинг с PHP.
 * Токен бота остаётся здесь, на сервере, и в браузер не попадает.
 *
 * Умеет два режима:
 *   1. POST с данными заказа из Mini App (основной)
 *   2. Webhook от Telegram с web_app_data, если открываете приложение
 *      кнопкой обычной клавиатуры и пользуетесь sendData()
 *
 * Настройка — см. README-miniapp.md
 */

// ─────────── НАСТРОЙКИ ───────────

const BOT_TOKEN = '8850533172:AAGlbphqhnQn60Eij5jJuVPhfpjGqSeXiEs';
const OWNER_CHAT_ID = '809023381';
const ALLOWED_ORIGIN = 'mirscents.ch104825.tw1.ru';

// Проверять подпись Telegram. Отключайте только для отладки в браузере.
const VERIFY_SIGNATURE = true;

// Не больше стольких заказов с одного IP в час. 0 — без ограничения.
const RATE_LIMIT = 5;

// ─────────── СЛУЖЕБНОЕ ───────────

header('Content-Type: application/json; charset=utf-8');
if (ALLOWED_ORIGIN !== '') {
    header('Access-Control-Allow-Origin: ' . ALLOWED_ORIGIN);
} else {
    header('Access-Control-Allow-Origin: *');
}
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST')    { fail('Только POST', 405); }
if (BOT_TOKEN === '')                          { fail('Не задан BOT_TOKEN', 500); }

$raw = file_get_contents('php://input');
if (strlen($raw) > 32768) { fail('Слишком большой запрос', 413); }

$in = json_decode($raw, true);
if (!is_array($in)) { fail('Некорректный JSON', 400); }

// Режим 2: пришёл webhook от Telegram
if (isset($in['update_id'])) {
    $wad = $in['message']['web_app_data']['data'] ?? null;
    if ($wad === null) { echo json_encode(['ok' => true]); exit; }   // прочие апдейты игнорируем
    $in = json_decode($wad, true);
    if (!is_array($in)) { echo json_encode(['ok' => true]); exit; }
} else {
    // Режим 1: прямой запрос из Mini App
    if (VERIFY_SIGNATURE && !checkInitData($in['initData'] ?? '')) {
        fail('Подпись Telegram не подтверждена', 403);
    }
    if (RATE_LIMIT > 0 && rateLimited()) {
        fail('Слишком много заказов, попробуйте позже', 429);
    }
}

$order = validate($in);
if (isset($order['error'])) { fail($order['error'], 400); }

$sent = tgSend(buildMessage($order));
if (!$sent) { fail('Не удалось передать заказ', 502); }

echo json_encode(['ok' => true, 'orderNo' => $order['orderNo']]);
exit;

// ─────────── ПРОВЕРКА ПОДПИСИ ───────────

/**
 * Telegram подписывает initData ключом, производным от токена бота.
 * Совпала подпись — значит, запрос действительно пришёл из Telegram,
 * а не от того, кто просто узнал адрес этого файла.
 */
function checkInitData(string $initData): bool
{
    if ($initData === '') return false;

    parse_str($initData, $data);
    $hash = $data['hash'] ?? '';
    if ($hash === '') return false;
    unset($data['hash']);

    ksort($data);
    $pairs = [];
    foreach ($data as $k => $v) { $pairs[] = $k . '=' . $v; }
    $checkString = implode("\n", $pairs);

    $secret = hash_hmac('sha256', BOT_TOKEN, 'WebAppData', true);
    $calc   = bin2hex(hash_hmac('sha256', $checkString, $secret, true));

    if (!hash_equals($calc, $hash)) return false;

    // Ссылка живёт сутки — защищает от повторной отправки старых данных
    $authDate = (int)($data['auth_date'] ?? 0);
    return $authDate > 0 && (time() - $authDate) < 86400;
}

function rateLimited(): bool
{
    $ip   = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $file = sys_get_temp_dir() . '/ms_rl_' . md5($ip);
    $now  = time();

    $hits = [];
    if (is_file($file)) {
        $hits = array_filter((array)json_decode((string)file_get_contents($file), true),
                             fn($t) => $now - (int)$t < 3600);
    }
    if (count($hits) >= RATE_LIMIT) return true;

    $hits[] = $now;
    @file_put_contents($file, json_encode(array_values($hits)), LOCK_EX);
    return false;
}

// ─────────── ПРОВЕРКА ДАННЫХ ───────────

function validate(array $d): array
{
    $c       = is_array($d['customer'] ?? null) ? $d['customer'] : [];
    $fio     = clean($c['fio'] ?? '', 120);
    $phone   = clean($c['phone'] ?? '', 40);
    $address = clean($c['address'] ?? '', 400);

    if (mb_strlen($fio) < 3)                                  return ['error' => 'Не указано ФИО'];
    if (strlen(preg_replace('/\D/', '', $phone)) < 10)        return ['error' => 'Некорректный телефон'];
    if (mb_strlen($address) < 8)                              return ['error' => 'Не указан адрес'];

    $rawItems = is_array($d['items'] ?? null) ? array_slice($d['items'], 0, 50) : [];
    if (!$rawItems)                                           return ['error' => 'Пустой заказ'];

    $items = [];
    foreach ($rawItems as $i) {
        if (!is_array($i)) continue;
        $items[] = [
            'brand'  => clean($i['brand']  ?? '', 60),
            'name'   => clean($i['name']   ?? '', 80),
            'volume' => clean($i['volume'] ?? '', 20),
            'price'  => (float)($i['price'] ?? 0),
            'qty'    => max(1, min(99, (int)($i['qty'] ?? 1))),
        ];
    }
    if (!$items)                                              return ['error' => 'Пустой заказ'];

    $u = is_array($d['tgUser'] ?? null) ? $d['tgUser'] : null;

    return [
        'orderNo'  => clean($d['orderNo'] ?? '', 24) ?: '—',
        'fio'      => $fio,
        'phone'    => $phone,
        'address'  => $address,
        'items'    => $items,
        'total'    => (float)($d['total'] ?? 0),
        'carrier'  => clean($d['carrier'] ?? '', 40),
        'delivery' => (float)($d['delivery'] ?? 0),
        'zone'     => (int)($d['zone'] ?? 0),
        'city'     => clean($d['city'] ?? '', 60),
        'tgId'       => $u ? (int)($u['id'] ?? 0) : 0,
        'tgUsername' => $u ? clean($u['username'] ?? '', 40) : '',
    ];
}

function clean($v, int $max): string
{
    return mb_substr(trim((string)$v), 0, $max);
}

// ─────────── СБОРКА СООБЩЕНИЯ ───────────

function buildMessage(array $o): string
{
    $carriers = ['cdek' => 'СДЭК', 'ozon' => 'Ozon Доставка', 'post' => 'Почта России'];
    $zones    = [
        1 => 'Краснодарский край и Адыгея', 2 => 'Юг России и Крым',
        3 => 'Центр и Северо-Запад', 4 => 'Урал, Поволжье и Север',
        5 => 'Сибирь', 6 => 'Дальний Восток',
    ];

    $lines = [];
    $qty   = 0;
    foreach ($o['items'] as $n => $it) {
        $qty += $it['qty'];
        $lines[] = ($n + 1) . '. <b>' . esc($it['brand'] . ' ' . $it['name']) . '</b>, ' . esc($it['volume'])
                 . "\n    " . $it['qty'] . ' шт × ' . money($it['price'])
                 . ' = ' . money($it['price'] * $it['qty']);
    }

    $carrier = $carriers[$o['carrier']] ?? ($o['carrier'] ?: '—');
    $ship    = $o['delivery'] ? $carrier . ' ≈ ' . money($o['delivery']) : $carrier;
    $geo     = $o['city']
        ? $o['city'] . ($o['zone'] ? ', зона ' . $o['zone'] . ' — ' . ($zones[$o['zone']] ?? '') : '')
        : ($o['zone'] ? 'зона ' . $o['zone'] . ' (город не распознан)' : 'не рассчитана');

    $who = $o['tgUsername'] ? '@' . $o['tgUsername'] : ($o['tgId'] ? 'id ' . $o['tgId'] : '—');

    $tz = new DateTimeZone('Europe/Moscow');
    $at = (new DateTime('now', $tz))->format('d.m.Y, H:i');

    return implode("\n", [
        '🛍 <b>НОВЫЙ ЗАКАЗ ' . esc($o['orderNo']) . '</b>',
        '━━━━━━━━━━━━━━━━━━',
        '👤 <b>ФИО:</b> ' . esc($o['fio']),
        '📞 <b>Телефон:</b> ' . esc($o['phone']),
        '💬 <b>Telegram:</b> ' . esc($who),
        '📍 <b>Адрес:</b> ' . esc($o['address']),
        '',
        '📦 <b>СОСТАВ ЗАКАЗА</b>',
        implode("\n", $lines),
        '',
        '💰 <b>Товары: ' . money($o['total']) . '</b> (' . $qty . ' шт) — клиент отметил как оплаченные',
        '🚚 <b>Доставка:</b> ' . esc($ship),
        '🗺 <b>Направление:</b> Краснодар → ' . esc($geo),
        '⚠️ Доставка НЕ оплачена — согласовать с клиентом',
        '━━━━━━━━━━━━━━━━━━',
        '🕐 ' . $at . ' (МСК)',
    ]);
}

function esc(string $t): string
{
    return str_replace(['&', '<', '>'], ['&amp;', '&lt;', '&gt;'], $t);
}

function money(float $n): string
{
    return number_format(round($n), 0, ',', ' ') . ' ₽';
}

// ─────────── ОТПРАВКА ───────────

function tgSend(string $text): bool
{
    $payload = [
        'chat_id'                  => OWNER_CHAT_ID,
        'text'                     => $text,
        'parse_mode'               => 'HTML',
        'disable_web_page_preview' => true,
    ];

    $ch = curl_init('https://api.telegram.org/bot' . BOT_TOKEN . '/sendMessage');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_UNICODE),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 12,
    ]);
    $res = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);

    if ($res === false) { error_log('MIR SCENTS · cURL: ' . $err); return false; }

    $j = json_decode((string)$res, true);
    if (empty($j['ok'])) {
        error_log('MIR SCENTS · Telegram: ' . ($j['description'] ?? 'неизвестная ошибка'));
        return false;
    }
    return true;
}

function fail(string $msg, int $code): void
{
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}
