import os
import xml.etree.ElementTree as xml
import re
import logging
import argparse
from parsers import mozilla_parser
from parsers import microsoft_parser


PROXIES = dict()

# Настройка логера
logging.basicConfig(format=u'%(levelname)-8s [%(asctime)s] %(message)s', level=logging.DEBUG, filename=u'log.log')


# Удобный парсинг консольных аргументов
def argument_parsing():
    parser = argparse.ArgumentParser(description=u'vuln_crawler v0.04 - скрипт получает список уязвимостей с сайта '
                                                 u'Mozilla Foundation и представляет их в XML виде.',
                                     epilog='made by Alexey Shcherbakov, 2017',
                                     add_help=True)
    parser.add_argument('-o',
                        action='store',
                        type=str,
                        default='vuln.xml',
                        dest='output_path',
                        help=u'Путь к выходному  XML-файлу (по умолчанию: текущая директория, файл vuln.xml)')
    parser.add_argument('-p',
                        action='store',
                        type=str,
                        default=None,
                        dest='proxy',
                        help=u'Данные прокси сервера в формате х.х.х.х:port')
    parser.add_argument(action='store',
                        type=str,
                        dest='vendor',
                        help=u'Введите вендора, чьи бюллютени будут парситься (возможные варианты '
                             u'MF - Moziila Foundation '
                             u'MS - Microsoft Corp.)'
                        )
    return parser.parse_args()


# Проверка существования xml файла и реализация дозаписи в него
def check_db_exsist(output_path, vendor):


    if os.path.exists(output_path):
        if vendor == 'MF':
            logging.debug('БД существовала, будет осуществлена проверка')
            # Если есть БД, то вернуть первый идентификатор в форме числа
            tree = xml.parse(output_path)
            root = tree.getroot()
            identifier = None
            for child in root.iterfind('./vul/identifier'):
                if 'Mozilla' in child.text:
                    identifier = child.text
                    break

            if identifier is None:
                return 0, 0
            else:
                return map(int, re.findall('\d+.\d+', identifier)[0].split('-'))

        if vendor == 'MS':
            logging.debug('БД существовала, будет осуществлена проверка')
            # Если есть БД, то вернуть первый идентификатор в форме числа
            tree = xml.parse(output_path)
            root = tree.getroot()
            identifier = None
            for child in root.iterfind('./vul/identifier'):
                if 'MS' in child.text:
                    identifier = child.text

            if identifier is None:
                return 0, 0
            else:
                return map(int, re.search('\d+-\d+', identifier).group(0).split('-'))
    else:
        # Если БД отсутвует, создать ее
        logging.debug('БД не существовала, будет создана новая БД')
        vuln = xml.Element('vulnerabilities')
        xml.ElementTree(vuln).write(output_path, encoding='utf-8')
        return 0, 0


# Функция запуска
def run():
    logging.debug('Программа запущена')

    args = argument_parsing()
    # if args.proxy is not None:
    #     PROXIES['http'] = args.proxy
    #     PROXIES['https'] = args.proxy

    print('Начинается парсинг')

    output_path = args.output_path
    year, num = check_db_exsist(output_path, args.vendor)

    if args.vendor == 'MF':
        mozilla_parser.run_mf_parsing(args.proxy, output_path, year, num)

    elif args.vendor == 'MS':
        microsoft_parser.run_ms_parsing(args.proxy, output_path, year, num)

    logging.debug('\nПрограмма отработала успешно')
    print('\nПрограмма отработала успешно')



# Точка входа в программу
if __name__ == '__main__':
    # test_run()
    run()
