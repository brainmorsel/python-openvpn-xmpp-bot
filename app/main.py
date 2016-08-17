import configparser
import logging
import sqlite3
import uuid
import ipaddress
import subprocess

import click
from sleekxmpp import ClientXMPP


SQL_CREATE_TABLE_REQUESTS = '''
    CREATE TABLE requests (
        id INTEGER PRIMARY KEY,
        timestamp INTEGER NOT NULL DEFAULT CURRENT_TIMESTAMP,
        user TEXT NOT NULL,
        access_targets TEXT NOT NULL DEFAULT '',
        ack INTEGER NOT NULL DEFAULT 0,
        approved INTEGER NOT NULL DEFAULT 0,
        key_download_url TEXT,
        ip_addr TEXT
    )
'''

PRESENCE_TEXT = '''Отправьте "help", чтобы получить подсказку.'''
HELP_TEXT = '''Чтобы запросить доступ к VPN серверу отправьте "request {список}".
Где {список} - список сервисов (через пробел) к которым нужен доступ:
'''
HELP_TEXT_FOR_APPROVERS = '''

Дополнительные команды:
  list - список пользователий и их прав.
  revoke {номер} {список} - запретить доступ к указаным сервисам.
  revoke {номер} #all - запретить доступ ко всем сервисам.
  mykey - получить ссылку на свой ключ.'''
REQUEST_MSG_TEXT = '''{who} запросил доступ к {accs}.
Номер запроса: {req_id}.
approve {req_id} - чтобы разрешить,
decline {req_id} [текст причины отказа] - чтобы отказать.'''
APPROVE_REPLY_MSG = '''Ваш запрос #{req_id} одобрен.
Чтобы скачать ключ доступа, перейдите по ссылке: {url}
Клиент для Windows: https://openvpn.net/index.php/open-source/downloads.html
Клиент для OS X: https://tunnelblick.net
Клиент для Linux: ищите в своём репозитории openvpn.

Все перечисленные клиенты принимают файл .ovpn в качестве конфига, остальные файлы в архиве -- на всякий случай.
'''


class Bot(ClientXMPP):
    def __init__(self, config):
        jid = config['xmpp']['jid']
        password = config['xmpp']['password']
        ClientXMPP.__init__(self, jid, password)
        self._approvers = config['approvers'].keys()
        self._db = config['database']['path']
        self._make_key_script = config['scripts']['make-key']
        self._update_access_script = config['scripts']['update-access']
        self._available_services = config['services'].keys()
        self._ip_pool_start = ipaddress.IPv4Address(config['ip-pool']['start'])
        self._ip_pool_size = config['ip-pool'].getint('size')
        self._key_url_format = config['key']['download-url']

        self._help_services_descr = '\n'.join((
            '    {0} - {1}'.format(s, d) for s, d in config['services'].items()
        ))

        self.add_event_handler('session_start', self.session_start)
        self.add_event_handler('message', self.message)

    def session_start(self, event):
        self.send_presence(pstatus=PRESENCE_TEXT, pshow='available')
        self.get_roster()

    def message(self, msg):
        if msg['type'] in ('chat', 'normal'):
            msg_body = msg['body'].strip()
            if msg_body == 'help':
                self.handle_help(msg)
            elif msg_body == 'list':
                self.handle_list(msg)
            elif msg_body == 'mykey':
                self.handle_mykey(msg)
            elif msg_body.startswith('request '):
                self.handle_access_request(msg)
            elif msg_body.startswith('approve ') or msg_body.startswith('decline '):
                self.handle_access_ack(msg)
            elif msg_body.startswith('revoke '):
                self.handle_access_revoke(msg)
            else:
                msg.reply('Извините, не понимаю. Отправьте "help", чтобы получить подсказку.').send()

    def handle_help(self, msg):
        msg_sender = msg.get_from().bare
        help_text = HELP_TEXT + self._help_services_descr
        if msg_sender in self._approvers:
            help_text += HELP_TEXT_FOR_APPROVERS
        msg.reply(help_text).send()
    
    def handle_access_request(self, msg):
        msg_sender = msg.get_from().bare
        msg_body = msg['body'].strip()
        access_targets = msg_body.split()[1:]
        if not access_targets:
            msg.reply('Нужно указать список сервисов.').send()
            return
        for target in access_targets:
            if target not in self._available_services:
                msg.reply('Ничего не знаю про "{0}".'.format(target)).send()
                return

        db = sqlite3.connect(self._db)
        c = db.cursor()
        try:
            c.execute('SELECT id FROM requests WHERE user = ? AND ack = 0', (msg_sender,))
            unapproved_req_id = c.fetchone()
            if unapproved_req_id is not None:
                unapproved_req_id = unapproved_req_id[0]
                msg.reply('Ваш последний запрос #{0} на рассмотрении. Ожидайте решения.'.format(unapproved_req_id)).send()
                return

            c.execute('SELECT access_targets, key_download_url, ip_addr FROM requests WHERE user = ? AND approved = 1 ORDER BY timestamp', (msg_sender,))
            old_access_targets = None
            key_download_url = None
            ip_addr = None
            # get save data from last item if exists
            for row in c:
                old_access_targets, key_download_url, ip_addr = row

            if old_access_targets:
                old_access_targets = set(old_access_targets.split())
                if old_access_targets == set(access_targets):
                    msg.reply('Запрошеный уровень доступа совпадает с тем, что у вас уже есть.').send()
                    return

            c.execute('INSERT INTO requests (user, access_targets, key_download_url, ip_addr) VALUES (?, ?, ?, ?)',
                    (msg_sender, ' '.join(access_targets), key_download_url, ip_addr))
            req_id = c.lastrowid
            db.commit()
        finally:
            db.close()

        req_msg = REQUEST_MSG_TEXT.format(who=msg_sender, accs=' '.join(access_targets), req_id=req_id)
        for approver in self._approvers:
            self.sendMessage(mtype='chat', mto=approver, mbody=req_msg)
        msg.reply('Ожидайте подтверждения запроса.').send()

    def handle_access_ack(self, msg):
        msg_sender = msg.get_from().bare
        if msg_sender not in self._approvers:
            msg.reply('Вы не можете этого сделать.').send()
            return

        msg_body = msg['body'].strip()
        tokens = msg_body.split()
        if len(tokens) < 2:
            msg.reply('Нужно указать номер запроса.').send()
            return
        action = tokens[0]
        req_id = int(tokens[1])
        extra_text = ' '.join(tokens[2:])

        db = sqlite3.connect(self._db)
        c = db.cursor()
        try:
            c.execute('SELECT user, access_targets, key_download_url, ip_addr FROM requests WHERE id = ? AND ack = 0', (req_id,))
            row = c.fetchone()
            if row is None:
                msg.reply('Запрос #{0} не существует или уже рассмотрен.'.format(req_id)).send()
                return
            user, access_targets, key_download_url, ip_addr = row
            access_targets = access_targets.split()
            if action == 'decline':
                c.execute('UPDATE requests SET ack = 1, approved = 0 WHERE id = ?', (req_id,))
                db.commit()
                msg.reply('Запрос #{0} отклонён.'.format(req_id)).send()
                decline_msg = 'Запрос #{0} на доступ к ({1}) отклонён.'.format(req_id, ', '.join(access_targets))
                if extra_text:
                    decline_msg += ' Причина: ' + extra_text
                self.sendMessage(mtype='chat', mto=user, mbody=decline_msg)
                return
            # action == 'approve'
            # закрыть предыдущую заявку, если есть
            c.execute('UPDATE requests SET approved = 0 WHERE user = ?', (user,))
            if key_download_url:
                c.execute('UPDATE requests SET ack = 1, approved = 1 WHERE id = ?', (req_id,))
            else:
                pool_ips = set()
                used_ips = set()
                for i in range(self._ip_pool_size):
                    pool_ips.add(self._ip_pool_start + i)

                c.execute('SELECT ip_addr FROM requests WHERE ip_addr IS NOT NULL')
                for row in c:
                    used_ips.add(ipaddress.IPv4Address(row[0]))
                free_ips = pool_ips - used_ips
                if len(free_ips) == 0:
                    msg.reply('Запрос #{0} невозможно одобрить. Нет свободных IP адресов.'.format(req_id)).send()
                    return

                ip_addr = str(free_ips.pop())
                key_uuid = uuid.uuid4().hex
                key_download_url = self._key_url_format.format(user=user, key_uuid=key_uuid)
                # подтвердить текущую
                c.execute('UPDATE requests SET ack = 1, approved = 1, key_download_url = ?, ip_addr = ? WHERE id = ?', (key_download_url, ip_addr, req_id,))
                self.make_key_download(user, key_uuid)
            db.commit()

            self.update_access_targets(user, access_targets, ip_addr)

            approve_msg = APPROVE_REPLY_MSG.format(req_id=req_id, url=key_download_url)
            self.sendMessage(mtype='chat', mto=user, mbody=approve_msg)
            #msg.reply('Запрос #{0} одобрен.'.format(req_id)).send()
            msg_approved = '{0} одобрил запрос #{1}'.format(msg_sender, req_id)
            for approver in self._approvers:
                self.sendMessage(mtype='chat', mto=approver, mbody=msg_approved)

        finally:
            db.close()

    def handle_list(self, msg):
        db = sqlite3.connect(self._db)
        c = db.cursor()
        try:
            c.execute('SELECT id, user, ip_addr, access_targets FROM requests WHERE approved = 1')
            user_list = []
            for req_id, user, ip_addr, access_targets in c:
                user_list.append('  #{0} {1} ({2}): {3}'.format(req_id, user, ip_addr, access_targets))
            msg.reply('Список активных пользователей их уровень доступа:\n' + '\n'.join(user_list)).send()
        finally:
            db.close()

    def handle_mykey(self, msg):
        msg_sender = msg.get_from().bare

        db = sqlite3.connect(self._db)
        c = db.cursor()
        try:
            c.execute('SELECT key_download_url FROM requests WHERE approved = 1 AND user = ?', (msg_sender,))
            row = c.fetchone()
            if row:
                key_download_url, = row
                msg.reply('Ссылка на ваш ключ: {0}'.format(key_download_url)).send()
            else:
                msg.reply('У вас ничего нет.').send()
        finally:
            db.close()

    def handle_access_revoke(self, msg):
        msg_sender = msg.get_from().bare
        if msg_sender not in self._approvers:
            msg.reply('Вы не можете этого сделать.').send()
            return

        msg_body = msg['body'].strip()
        tokens = msg_body.split()
        req_id = tokens[1]
        revoke_list = tokens[2:]

        if len(revoke_list) == 0:
            msg.reply('Нужно указать список отзываемых прав.').send()
            return

        db = sqlite3.connect(self._db)
        c = db.cursor()
        try:
            c.execute('SELECT user, ip_addr, access_targets FROM requests WHERE approved = 1 and id = ?', (req_id,))
            row = c.fetchone()
            if row is None:
                msg.reply('Запрос #{0} не найден.'.format(req_id)).send()
                return
            user, ip_addr, access_targets = row
            if revoke_list[0] == '#all':
                access_targets = []
            else:
                access_targets = list(set(access_targets.split()) - set(revoke_list))
            c.execute('UPDATE requests SET access_targets = ? WHERE id = ?',
                      (' '.join(access_targets), req_id))
            db.commit()
        finally:
            db.close()

        self.update_access_targets(user, access_targets, ip_addr)
        msg_revoked = '{0} запретил доступ {1} к {2}'.format(msg_sender, user, ' '.join(revoke_list))
        for approver in self._approvers:
            self.sendMessage(mtype='chat', mto=approver, mbody=msg_revoked)
        self.sendMessage(mtype='chat', mto=user, mbody=msg_revoked)

    def make_key_download(self, user, key_uuid):
        subprocess.run([self._make_key_script, user, key_uuid])

    def update_access_targets(self, user, access_targets, ip_addr):
        subprocess.run([self._update_access_script, user, ip_addr] + access_targets)


@click.command()
@click.option('-c', '--config', 'config_file', required=True)
@click.option('-l', '--log-level', default='info')
def cli(config_file, log_level):
    level = getattr(logging, log_level.upper())
    logging.basicConfig(level=level,
                        format='%(levelname)-8s %(message)s')

    config = configparser.ConfigParser(allow_no_value=True)
    config.read(config_file)

    db = sqlite3.connect(config['database']['path'])
    with db as c:
        try:
            c.execute(SQL_CREATE_TABLE_REQUESTS)
            db.commit()
        except sqlite3.OperationalError as e:
            pass  # table exists
    db.close()
    
    xmpp = Bot(config)
    xmpp.connect()
    xmpp.process(block=True)
