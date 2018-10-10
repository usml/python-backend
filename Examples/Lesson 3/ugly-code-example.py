#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pika
import os
import sys
import json
import syslog
import time
import re
import requests
import telegram
from threading import Thread


def Supervisor(thr_list):
    thr = []

    for thread_name in thr_list:
        thr.append(None)

    while True:
        i = 0
        for thread_name in thr_list:
            if not thr[i] or not thr[i].is_alive():
                thr[i] = Thread(target=thread_name)
                thr[i].daemon = True
                thr[i].start()
                syslog.syslog("Starting thread for: %s" % str(thread_name))
            thr[i].join(1)
            i = i + 1

        time.sleep(10)


def db_process_two(row):
    if not row:
        return False
    zhost = row[7]
    try:
        connection = dbModule.Connection("db_login/db_pass")
    except dbModule.DatabaseError as exc:
        syslog.syslog("DB connection error: %s" % exc)
        return False

    try:
        cursor = connection.cursor()
        statTT = cursor.var(dbModule.STRING, 255)
        result = cursor.var(dbModule.NUMBER, 255)
        numTT = cursor.var(dbModule.NUMBER, 255)
        cursor.prepare("""BEGIN
        procedure_two(:1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11);
        END;""")
        row.append(result)
        row.append(numTT)
        row.append(statTT)
        cursor.execute(None, row)
        connection.commit()
        cursor.close()
        syslog.syslog("Insert data to db: %s" % row[0])
    except Exception as exc:
        syslog.syslog("Error while inserting to db: %s" % exc)
        return False

    syslog.syslog(str(row))
    event_num = re.search("\s*([0-9]+)", row[3]).group(1)
    event_reg_num = row[-2].getvalue()
    if event_reg_num == None:
        event_reg_num = 0
    event_reg_status = str(row[-1].getvalue())
    resultTT = (int(event_reg_num), event_reg_status)
    syslog.syslog("Prepare ack two: %s" % row)
    return (zhost, event_num, resultTT)


def db_process_one(row):
    if not row:
        return False
    zhost = row[7]

    try:
        connection = dbModule.Connection("db_login/db_pass")
    except dbModule.DatabaseError as exc:
        syslog.syslog("DB connection error: %s" % exc)
        return False

    try:
        cursor = connection.cursor()
        statTT = cursor.var(dbModule.STRING, 255)
        result = cursor.var(dbModule.NUMBER, 255)
        numTT = cursor.var(dbModule.NUMBER, 255)
        cursor.prepare("""BEGIN;
            procedure_one(:1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11);
        ); END;""")
        row.append(result)
        row.append(numTT)
        row.append(statTT)
        cursor.execute(None, row)
        connection.commit()
        cursor.close()
        syslog.syslog("Insert data to db: %s" % row[0])
    except Exception as exc:
        syslog.syslog("Error while inserting to db: %s" % exc)
        return False

    event_num = re.search("\s*([0-9]+)", row[6]).group(1)
    resultTT = (int(row[-3].getvalue()),
                int(row[-2].getvalue()), str(row[-1].getvalue()))

    syslog.syslog("Prepare ack one: %s" % row)
    return (zhost, event_num, resultTT)


def db_process_three(row):
    if not row:
        return False
    try:
        connection = dbModule.Connection("db_login/db_pass")
    except dbModule.DatabaseError as exc:
        syslog.syslog("DB connection error: %s" % exc)
        return False

    try:
        cursor = connection.cursor()
        cursor.prepare("""BEGIN;
            procedure_three(:1, :2, :3);
            END;""")
        cursor.execute(None, row)
        connection.commit()
        syslog.syslog("Insert data to db: %s" % row[0])
    except Exception as exc:
        syslog.syslog("Error while inserting to db: %s" % exc)
        return False

    return True


def start_consume_one():
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='localhost')
        )

        channel = connection.channel()
        channel.queue_declare(queue='queue_one', durable=True)
        channel.basic_consume(callback_one,
                              queue='queue_one',
                              no_ack=False, arguments={"x-priority": 5})

        channel.basic_qos(prefetch_count=1)
        channel.start_consuming()
    except Exception as exc:
        channel.stop_consuming()
        syslog.syslog("Error while consuming queue one: %s" % exc)

    connection.close()
    sys.exit(1)


def start_consume_two():
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='localhost')
        )
        channel = connection.channel()
        channel.queue_declare(queue='queue_two', durable=True)
        channel.basic_consume(callback_two,
                              queue='queue_two',
                              no_ack=False)

        channel.basic_qos(prefetch_count=1)
        channel.start_consuming()
    except Exception as exc:
        channel.stop_consuming()
        syslog.syslog("Error while consuming queue two: %s" % str(exc))

    connection.close()
    sys.exit(1)


def start_consume_three():
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='localhost')
        )

        channel = connection.channel()
        channel.queue_declare(queue='queue_three', durable=True)
        channel.basic_consume(callback_three,
                              queue='queue_three',
                              no_ack=False)

        channel.basic_qos(prefetch_count=1)
        channel.start_consuming()
    except Exception as exc:
        channel.stop_consuming()
        syslog.syslog("Error while consuming queue three: %s" % str(exc))

    connection.close()
    sys.exit(1)


def start_consume_mail():
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='localhost')
        )

        channel = connection.channel()
        channel.queue_declare(queue='queue_mail', durable=True)
        channel.basic_consume(callback_mail,
                              queue='queue_mail',
                              no_ack=True)

        channel.basic_qos(prefetch_count=1)
        channel.start_consuming()
    except Exception as exc:
        channel.stop_consuming()
        syslog.syslog("Error while consuming queue mail: %s" % str(exc))

    connection.close()
    sys.exit(1)


def start_consume_sms():
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='localhost')
        )

        channel = connection.channel()
        channel.queue_declare(queue='queue_sms', durable=True)
        channel.basic_consume(callback_sms,
                              queue='queue_sms',
                              no_ack=True
                              )

        channel.basic_qos(prefetch_count=1)
        channel.start_consuming()
    except Exception as exc:
        channel.stop_consuming()
        syslog.syslog("Error while consuming queue sms: %s" % str(exc))
    connection.close()
    sys.exit(1)


def start_consume_telegram():
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='localhost')
        )

        channel = connection.channel()
        channel.queue_declare(queue='queue_tlgrm', durable=True)
        channel.basic_consume(callback_telegram,
                              queue='queue_tlgrm',
                              no_ack=True
                              )

        channel.basic_qos(prefetch_count=1)
        channel.start_consuming()
    except Exception as exc:
        channel.stop_consuming()
        syslog.syslog("Error while consuming queue tlgrm: %s" % str(exc))

    connection.close()
    sys.exit(1)


def send_sms(body_sms):
    smsDict = json.loads(body_sms)

    number = smsDict['number']
    subject = smsDict['subject']
    message = smsDict['message']

    message = subject+" "+message
    message = message.replace('\n', '')
    message = message[:70].encode('utf-8')

    try:
        connection = dbModule.Connection("db_login/db_pass")
        cursor = connection.cursor()

        sql = "DECLARE res_v VARCHAR (100); \
        BEGIN send_procedure(%s, %s); COMMIT; END;"\
            % (number.encode('utf-8'), message)

        cursor.execute(sql)

        syslog.syslog("Sending SMS message to: %s" % (smsDict['number']))
    except Exception as exc:
        syslog.syslog("Error while sending SMS notification: %s" % (exc))

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def send_telegram(body_telegram):
    try:
        # Telegram Bot
        pp = telegram.utils.request.Request(proxy_url='socks5://0.0.0.0:9999', urllib3_proxy_kwargs={
                                            'username': 'some_username', 'password': 'some_password'})
        bot = telegram.Bot(
            token='id:token', request=pp)

        telegramData = json.loads(body_telegram)
        bot.sendMessage(telegramData['channel'], telegramData['message'])
    except Exception as exc:
        syslog.syslog("Error while sending telegram: %s" % (exc))


def send_mail(body_msg):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.header import Header
    from validate_email import validate_email

    try:
        my_mail = 'mail@mail.server'
        mailDict = json.loads(body_msg)
        mail_is_valid = validate_email(mailDict['mail'])

        if mail_is_valid is not True:
            raise Exception("invalid e-mail: " + mailDict['mail'])

        msg = MIMEMultipart('alternative')
        msg['Subject'] = Header(mailDict['subject'], 'utf-8')
        msg['From'] = my_mail
        msg['To'] = mailDict['mail']

        msgText = MIMEText(mailDict['message'].encode(
            'utf-8'), 'plain', 'utf-8')
        msg.attach(msgText)

        s = smtplib.SMTP('mail.server')
        s.sendmail(my_mail, mailDict['mail'], msg.as_string())

        syslog.syslog("Sending email-massage to: %s" % (mailDict['mail']))
    except Exception as exc:
        syslog.syslog("Error while sending e-mail: %s" % (exc))

    finally:
        if s:
            s.quit()

def create_one(body_msg):
    tt = json.loads(body_msg)

    try:
        row = [
            tt['hostname'].encode('utf-8'),
            tt['hostname'].encode('utf-8'),
            tt['state-trigger'].encode('utf-8'),
            "Автоматически создано \nevent: " +
            str(tt['event'].encode('utf-8')),
            tt['check-type'].encode('utf-8'),
            int(tt['trigger']),
            tt['message'].encode('utf-8'),
            tt.get('zhost', 'some.host').encode('utf-8')
        ]

        syslog.syslog('Message: {} {} {}'.format(tt['hostname'].encode(
            'utf-8'), tt['message'].encode('utf-8'), tt['state-trigger'].encode('utf-8')))
        return row
    except Exception as exc:
        syslog.syslog("Error while creating: %s" % exc)
        return False

def create_two(body_msg):
    tt = json.loads(body_msg)
    try:
        row = [
            tt['hostname'].encode('utf-8'),
            tt['ip-address'].encode('utf-8'),
            tt['state-trigger'].encode('utf-8'),
            tt['message'].encode('utf-8'),
            tt['comment'].encode('utf-8'),
            tt['trigger'].encode('utf-8'),
            "Автоматически создано " +
            tt['prefix'].encode('utf-8')+"\nevent: " +
            tt['event'].encode('utf-8'),
            tt.get('zhost', 'some.host').encode('utf-8')
        ]

        syslog.syslog('Message: {} {} {}'.format(tt['hostname'].encode(
            'utf-8'), tt['message'].encode('utf-8'), tt['state-trigger'].encode('utf-8')))
        return row
    except Exception as exc:
        syslog.syslog("Error while creating: %s" % exc)
        return False

def create_three(body_msg):
    tt = json.loads(body_msg)
    try:
        row = [tt['hostname'].encode(
            'utf-8'), tt['state-trigger'].encode('utf-8'), tt['trigger'].encode('utf-8')]

        syslog.syslog('Three message: {} {} {}'.format(tt['hostname'].encode(
            'utf-8'), tt['message'].encode('utf-8'), tt['state-trigger'].encode('utf-8')))
        return row
    except Exception as exc:
        syslog.syslog("Error while creating: %s" % (exc))
        return False


def event_update_two(data):
    if not data:
        return False
    zhost, evid, NumTT = data

    server = 'server'
    if zhost == 'server2':
        server = 'server2'

    login = 'event_login'
    password = 'event_password'

    s = requests.Session()
    s.auth = (login, password)

    return True

def event_update_one(data):
    if not data:
        return False
    zhost, evid, NumTT = data

    server = 'server'
    if zhost == 'server2':
        server = 'server2'

    login = 'event_login'
    password = 'event_password'

    s = requests.Session()
    s.auth = (login, password)

    return True

def callback_one(ch, method, properties, body):
    row = create_one(body)
    db_result = db_process_one(row)
    result = event_update_one(db_result)
    if result:
        ch.basic_ack(delivery_tag=method.delivery_tag)
    else:
        ch.basic_nack(delivery_tag=method.delivery_tag)


def callback_two(ch, method, properties, body):
    row = create_two(body)
    db_result = db_process_two(row)
    result = event_update_two(db_result)
    if result:
        ch.basic_ack(delivery_tag=method.delivery_tag)
    else:
        ch.basic_nack(delivery_tag=method.delivery_tag)


def callback_three(ch, method, properties, body):
    row = create_three(body)
    db_result = db_process_three(row)
    if db_result:
        ch.basic_ack(delivery_tag=method.delivery_tag)
    else:
        ch.basic_nack(delivery_tag=method.delivery_tag)


def callback_sms(ch, method, properties, body):
    send_sms(body)


def callback_telegram(ch, method, properties, body):
    send_telegram(body)


def callback_mail(ch, method, properties, body):
    send_mail(body)


class telegram_api:
    def __init__(self, token, proxy={}):
        self.BOT_TOKEN = token
        self.cmd = {"stat": "getMe", "send": "sendMessage"}
        if proxy:
            ip = proxy['ip']
            port = proxy['port']
            user = proxy['user']
            passwd = proxy['password']
            pp = telegram.utils.request.Request(proxy_url='socks5://%s:%s' % (
                ip, port), urllib3_proxy_kwargs={'username': user, 'password': passwd})
        else:
            pp = telegram.utils.request.Request()
        self.bot = telegram.Bot(token=self.BOT_TOKEN, request=pp)

    def stat(self):
        # cmd=self.cmd["stat"]
        try:
            pass
        except Exception as err:
            messToSyslog = "Fail to read telegram_bot status: %s" % (err)
            syslog.syslog('-----------------------------------------')
            syslog.syslog(" %s" % messToSyslog)

    def send(self, chat, mess):
        # cmd = self.cmd["send"]
        mess = mess.encode('utf-8')
        try:
            self.bot.sendMessage(chat, mess)
            return True
        except Exception as err:
            messToSyslog = "Fail to sendmessage via telegram_bot: %s" % (err)
            syslog.syslog('-----------------------------------------')
            syslog.syslog(" %s" % messToSyslog)


class handler:
    def __init__(self, queue):
        self.queue = queue

        if queue == "queue_Tgm_1":
            self.notify = self.telegram
        elif queue == "queue_tlgrm":
            self.notify = self.psevdo_telegram
        else:
            self.notify = self.default

        self.params = {"telegram": {"token": "id:token",
                                    "base_url": "https://api.telegram.org/bot",
                                    'proxy': {
                                        'ip': '0.0.0.0',
                                        'port': 9999, 'user': 'some_user', 'password': 'some_password'}},
                       "to_db": {'url_in': 'some url in'}}

    def start_consume(self):
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(
                host='localhost'))
            channel = connection.channel()

            channel.queue_declare(queue=self.queue, durable=True)
            channel.basic_consume(self.callback,
                                  queue=self.queue,
                                  no_ack=False, exclusive=False)
            channel.basic_qos(prefetch_count=1)
            channel.start_consuming()
        except Exception as exc:
            # channel.stop_consuming()
            syslog.syslog("Error while consuming %s queue: %s" %
                          (self.queue, str(exc)))
        connection.close()
        sys.exit(1)

        connection.close()

    def callback(self, ch, method, properties, body):
        if self.notify(body):
            ch.basic_ack(delivery_tag=method.delivery_tag)

    def default(self, body):
        messToSyslog = "got " + body + " but not set notifyer"
        syslog.syslog("%s: %s" % (self.queue, messToSyslog))
        return True

    def telegram(self, body):
        syslog.syslog("%s: send data to telegramm %s" % (self.queue, body))
        params = self.params["telegram"]
        t = telegram_api(params["token"], proxy=params.get('proxy'))
        data = json.loads(body)
        chat_id = data["chat_id"]
        mess = data["message"]
        return t.send(chat_id, mess) or True

    def psevdo_telegram(self, body):
        params = self.params["to_db"]
        db = corporateDB(params['url_in'])
        data = json.loads(body)
        res, mess = db.telegram_procedure_exec(
            data['group'], data['message'])
        syslog.syslog("%s: send data for telegramm notification %s with status %s" % (
            self.queue, body, res))
        return True


class corporateDB:
    def __init__(self, url_in):
        self.connection = dbModule.Connection("login/password")
        self.cursor = self.connection.cursor()
        self.cursor.execute('''BEGIN
                            some_initial_procedure(%s);
                            END;''' % url_in)

    def telegram_procedure_exec(self, group, message):
        self.cursor.execute("""BEGIN
                        another_plsql_procedure(%s);
                        COMMIT;
                        END;""" % message, group=int(group), result_out=result_out, message_out=message_out)
        self.cursor.close()
        self.connection.commit()
        self.connection.close()
        return result_out.getvalue(), message_out.getvalue()


if __name__ == "__main__":
    syslog.openlog('some_tag', syslog.LOG_PID, syslog.LOG_NOTICE)

    try:
        thr_list = [
            start_consume_one,
            start_consume_two,
            start_consume_three,
            start_consume_mail,
            start_consume_sms,
            start_consume_telegram
        ]

        for n in ["queue_Tgm_1", "queue_tlgrm"]:
            t = handler(n)
            thr_list.append(t.start_consume)

        Supervisor(thr_list)

    except KeyboardInterrupt:
        print("EXIT")
        raise
