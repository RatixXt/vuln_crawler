import requests
import progressbar
import bs4
import os
import xml.etree.ElementTree as xml
from datetime import datetime
import re
import logging
import argparse

# Настройка логера
logging.basicConfig(format=u'%(levelname)-8s [%(asctime)s] %(message)s', level=logging.DEBUG, filename=u'log.log')


# Удобный парсинг консольных аргументов
def argument_parsing():
    parser = argparse.ArgumentParser(description=u'vuln_crawler v0.001 - скрипт получает список уязвимостей с сайта '
                                                 u'Mozilla Foundation и представляет их в XML виде.',
                                     epilog='made by Alexey Shcherbakov, 2017')
    parser.add_argument('-o',
                        action='store',
                        type=str,
                        default='vuln.xml',
                        dest='output_path',
                        help=u'Путь к выходному  XML-файлу (по умолчанию: текущая директория, файл vuln.xml)')

    return parser.parse_args()


# Функция находит ссылки на информацию об обновлениях безопасности с блога Mozilla
# Блог https://www.mozilla.org/en-US/security/advisories/
# url - ссылка на информацию об обновлении
# MFSA - id обновления безопасности от Mozilla
def get_update_urls(year=0, num=0):
    domain = 'https://www.mozilla.org/'
    blog_url = 'https://www.mozilla.org/en-US/security/advisories/'
    html_str = requests.get(blog_url).content
    soup = bs4.BeautifulSoup(html_str, 'html.parser')

    # Получаем список ссылок li с CSS классом level-item
    tags_li = soup.select('li.level-item')
    del soup

    urls = []

    for tag in tags_li:
        tag = tag.a
        if tag is not None:
            cur_year, cur_num = map(int, re.findall('\d+.\d+', tag.contents[0].contents[0])[0].split('-'))
            if (cur_year > year) or (cur_year == year and cur_num > num):
                urls.append({'url': '{}{}'.format(domain, tag.get('href')), 'MFSA': tag.contents[0].contents[0]})

    logging.debug('get_update_urls отработало без ошибок')
    return urls


# Функция для извлечения информации из разделов Summary
def summary_crawl(summary_tags, vuln_info):
    dt_tags = summary_tags.select('dt')
    dd_tags = summary_tags.select('dd')

    for num, tag in enumerate(dd_tags):
        # Сам Impact находится внутри тега <span></span>, поэтому его значение находится глубже
        if dt_tags[num].contents[0] == 'Impact':
            vuln_info[dt_tags[num].contents[0]] = tag.contents[0].contents[0]
        # Fixed in может представляет собой список внутри тега <ul></ul>, его необходимо извечь
        elif dt_tags[num].contents[0] == 'Fixed in':
            vuln_info[dt_tags[num].contents[0]] = [elem.contents[0] for elem in tag.select('li')]
        else:
            vuln_info[dt_tags[num].contents[0]] = tag.contents[0]
    return vuln_info


# Основная функция для парсинга URL с данными об уязвимостях
def parse_update_url(url):
    logging.debug('Начинается парсинг следующего URL:{}'.format(url))
    html_str = requests.get(url).content
    soup = bs4.BeautifulSoup(html_str, 'html.parser')

    list_vuln_info = list()
    vuln_info = dict()

    # Получение общих сведений об обновлении безопасности, помещаются в словарь summary
    # Impact - оценка воздействия, возможные значения: Low, Medium, High, Critical
    # Announced - дата выхода обновления
    # Reporter - обнаруживший уязвииость
    # Products - продукты для которых актуальна уязвимость
    # Fixed in - версия продукта устраняющая уязвимость
    # name - название уязвимости
    # MFSA - id обновления безопасности от Mozilla

    vuln_info['MFSA'] = soup.header.h1.contents[0]
    article_body = soup.find('div', itemprop='articleBody')
    del soup
    tags_summary = article_body.select('dl.summary')
    vuln_info['name'] = article_body.h2.contents[0]
    vuln_info = summary_crawl(tags_summary[0], vuln_info)

    # Получаем прочие сведения об уязвимости:
    # Description - описание уязвимости
    # Workaround - способ устранения уязвимости
    # References - источники, связанные с уязвимостью
    # CVE - id CVE

    # Следующие две закомментированные строчки кода определяют вид публикации по ее дате, но в случае перехода обратно
    # на публикации по одной уязвимости он работать не будет, поэтому он изменен на попытку получения списка уязвимостей
    # , если попытка неудачна, то используется парсинг для единичных уязвимостей
    # time_of_new_design = datetime.strptime('September 20, 2016', "%B %d, %Y")
    # if datetime.strptime(vuln_info['Announced'], "%B %d, %Y") < time_of_new_design:

    tags_cve = article_body.select('section.cve')

    if not tags_cve:
        # Уязвимости опубликованные до 20 сентября 2016 публиковались по одной и без использования CVE id
        tags_text_h = article_body.select('h3')
        tags_text = article_body.select('p')
        tags_ul = article_body.select('ul')

        for num, tag in enumerate(tags_text_h):
            if tag.contents[0] == 'References':
                # В некоторых случаях References содержатся не в тегах <p>, а в тегах <ul>, первый <ul> - это Fixed In
                if len(tags_ul) > 1:
                    vuln_info[tag.contents[0]] = [elem.get('href') for elem in tags_ul[1].select('a')]
                else:
                    # print(tags_text[num].contents)
                    try:
                        vuln_info[tag.contents[0]] = [elem.get('href') for elem in tags_text[num].contents]
                    except Exception as err:
                        logging.error('Произошла ощибка, связанная с наличием лишенего тега <p> '
                                      'для выделение дополнительного абзаца: {}'.format(err))
            elif tag.contents[0] == 'Description' and len(tags_ul) > 1:
                vuln_info[tag.contents[0]] = ''.join(map(str, tags_text[num].contents))
            else:
                vuln_info[tag.contents[0]] = tags_text[num].contents[0]
        vuln_info['CVE'] = '.'
        list_vuln_info.append(vuln_info)

    else:
        # Уязвимости опубликованные после 20 сентября 2016 публикуются сразу в большом количистве и с указанием CVE id
        # для каждой уязвимости

        # Для каждой уязвимости актуальна информация из summary, поэтому ее необходимо сохранить и добавлять к каждой
        # уязвимости
        summary_info = vuln_info.copy()

        for cve in tags_cve:
            vuln_info = summary_info.copy()
            vuln_info['CVE'] = cve.h4.get('id')

            # Каждая уязвимость содержит в себе дополнительный summary, который может оказать влияние на общий summary
            # в частности - это Impact
            mini_summary = cve.select('dl.summary')
            vuln_info = summary_crawl(mini_summary[0], vuln_info)

            tags_h5 = cve.select('h5')
            tags_text = cve.select('p')
            tags_ul = cve.select('ul')

            for tag in tags_h5:
                if tag.contents[0] == 'References':
                    # References содержатся в тегах <ul>, необходимо извлекать
                    vuln_info[tag.contents[0]] = [elem.get('href') for elem in tags_ul[0].select('a')]
                else:
                    vuln_info[tag.contents[0]] = tags_text[0].contents[0]
            list_vuln_info.append(vuln_info)
    logging.debug('Парсинг URL успешно закончен')

    return list_vuln_info


# Проверка существования xml файла и реализация дозаписи в него
def check_db_exsist(output_path):
    if os.path.exists(output_path):
        logging.debug('БД существовала, будет осуществлена проверка')
        # Если есть БД, то вернуть первый идентификатор в форме числа
        tree = xml.parse(output_path)
        return map(int, re.findall('\d+.\d+', tree.findtext('./vul/identifier'))[0].split('-'))
    else:
        # Если БД отсутвует, создать ее
        logging.debug('БД не существовала, будет создана новая БД')
        vuln = xml.Element('vulnerabilities')
        xml.ElementTree(vuln).write(output_path, encoding='utf-8')
        return 0, 0


# Преобразование данных в XML
def to_xml(output_path, data):
    logging.debug('Начался парсинг данных в xml')
    tree = xml.parse(output_path)
    root = tree.getroot()

    list_xml_vuln = list()
    for vuln in data:
        vul = xml.Element('vul')
        identifier = xml.SubElement(vul, 'identifier')
        identifier.text = vuln['MFSA']

        description = xml.SubElement(vul, 'description')
        description.text = vuln['Description']

        vuln_soft = xml.SubElement(vul, 'vulnerable_software')
        for product in vuln['Products'].split(', '):
            soft = xml.SubElement(vuln_soft, 'soft')
            vendor = xml.SubElement(soft, 'vendor')
            vendor.text = 'Mozilla Foundation'
            # Можно указывать версию в которой уже исправлено, но как поулчить версии для которых актуально, не ясно
            version = xml.SubElement(soft, 'version')
            version.text = '.'
            types = xml.SubElement(soft, 'types')
            type_ = xml.SubElement(types, 'type')
            if re.search('Firefox OS', product):
                type_.text = 'ОС'
                enviroment = xml.SubElement(vul, 'enviroment')
                os_ = xml.SubElement(enviroment, 'os')
                vendor = xml.SubElement(os_, 'vendor')
                vendor.text = 'Mozilla Foundation'
                name = xml.SubElement(os_, 'name')
                name.text = 'Firefox OS'
                version = xml.SubElement(os_, 'version')
                version.text = '.'
                platform = xml.SubElement(os_, 'platform')
                platform.text = 'ARM'

            elif re.search('Firefox', product):

                type_.text = 'Браузер'
                systems = [{'os': 'Windows', 'vendor': 'Microsoft Corp.'},
                           {'os': 'Linux', 'vendor': 'The Linux Foundation'},
                           {'os': 'MacOS', 'vendor': 'Apple'}]
                platforms = ['x86', 'x64']
                enviroment = xml.SubElement(vul, 'enviroment')
                for system_ in systems:
                    for platform_ in platforms:
                        os_ = xml.SubElement(enviroment, 'os')
                        vendor = xml.SubElement(os_, 'vendor')
                        vendor.text = system_['vendor']
                        name = xml.SubElement(os_, 'name')
                        name.text = system_['os']
                        version = xml.SubElement(os_, 'version')
                        version.text = '.'
                        platform = xml.SubElement(os_, 'platform')
                        platform.text = platform_

            elif re.search('Thunderbird', product):
                type_.text = 'Почтовая программа'
                systems = [{'os': 'Windows', 'vendor': 'Microsoft Corp.'},
                           {'os': 'Linux', 'vendor': 'The Linux Foundation'},
                           {'os': 'MacOS', 'vendor': 'Apple'}]
                platforms = ['x86', 'x64']
                enviroment = xml.SubElement(vul, 'enviroment')
                for system_ in systems:
                    for platform_ in platforms:
                        os_ = xml.SubElement(enviroment, 'os')
                        vendor = xml.SubElement(os_, 'vendor')
                        vendor.text = system_['vendor']
                        name = xml.SubElement(os_, 'name')
                        name.text = system_['os']
                        version = xml.SubElement(os_, 'version')
                        version.text = '.'
                        platform = xml.SubElement(os_, 'platform')
                        platform.text = platform_

            elif re.search('SeaMonkey', product):
                type_.text = 'Браузер'
                type_ = xml.SubElement(types, 'type')
                type_.text = 'Почтовая программа'
                type_ = xml.SubElement(types, 'type')
                type_.text = 'IRC-клиент'
                type_ = xml.SubElement(types, 'type')
                type_.text = 'редактор HTML'
                systems = [{'os': 'Windows', 'vendor': 'Microsoft Corp.'},
                           {'os': 'Linux', 'vendor': 'The Linux Foundation'},
                           {'os': 'MacOS', 'vendor': 'Apple'}]

                enviroment = xml.SubElement(vul, 'enviroment')
                for system_ in systems:
                    os_ = xml.SubElement(enviroment, 'os')
                    vendor = xml.SubElement(os_, 'vendor')
                    vendor.text = system_['vendor']
                    name = xml.SubElement(os_, 'name')
                    name.text = system_['os']
                    version = xml.SubElement(os_, 'version')
                    version.text = '.'
                    platform = xml.SubElement(os_, 'platform')
                    platform.text = 'x86'
            else:
                type_.text = '.'
                enviroment = xml.SubElement(vul, 'enviroment')
                os_ = xml.SubElement(enviroment, 'os')
                vendor = xml.SubElement(os_, 'vendor')
                vendor.text = '.'
                name = xml.SubElement(os_, 'name')
                name.text = '.'
                version = xml.SubElement(os_, 'version')
                version.text = '.'
                platform = xml.SubElement(os_, 'platform')
                platform.text = '.'

        cwe = xml.SubElement(vul, 'cwe')
        identifier = xml.SubElement(cwe, 'identifier')
        identifier.text = '.'

        # Не совсем верно, но дата обнаружения будет ставится как дата исправления
        identify_date = xml.SubElement(vul, 'identify_date')
        identify_date.text = datetime.strptime(vuln['Announced'], "%B %d, %Y").strftime('%d.%m.%Y')

        cvss = xml.SubElement(vul, 'cvss')
        vector = xml.SubElement(cvss, 'vector')
        vector.text = '.'

        severity = xml.SubElement(vul, 'severity')
        severity.text = vuln['Impact']

        solution = xml.SubElement(vul, 'solution')
        if vuln.get('Workaround') is not None:
            solution.text = vuln['Workaround']
        else:
            solution.text = 'Обновить версию ПО до {}'.format(', '.join(vuln['Fixed in']))

        vul_status = xml.SubElement(vul, 'vul_status')
        vul_status.text = 'Подтверждена производителем'

        exploit_status = xml.SubElement(vul, 'exploit_status')
        exploit_status.text = '.'

        fix_status = xml.SubElement(vul, 'fix_status')
        fix_status.text = 'Уязвимость устранена'

        sources = xml.SubElement(vul, 'sources')
        if vuln.get('References') is not None:
            for link in vuln['References']:
                source = xml.SubElement(sources, 'source')
                source.text = link

        other = xml.SubElement(vul, 'other')
        other.text = '.'
        list_xml_vuln.append(vul)
        root.insert(0, vul)
    try:
        xml.ElementTree(root).write(output_path, encoding='utf-8')
    except Exception as err:
        logging.error("Произошла неизвестная ошибка: {}".format(err))

    logging.debug('Парсинг данных в xml успешно завершен')


# Функция запуска
def run():
    logging.debug('Программа запущена')

    args = argument_parsing()

    print('Начинается парсинг')

    output_path = args.output_path
    year, num = check_db_exsist(output_path)
    links = get_update_urls(year, num)
    links.reverse()


    bar = progressbar.ProgressBar(max_value=len(links))
    for num, link in enumerate(links):

        # Все условия пропускают ссылки, которые парсятся с ошибками
        if link['MFSA'] == 'MFSA 2011-35' or link['MFSA'] == 'MFSA 2011-34' or link['MFSA'] == 'MFSA 2011-33' \
                or link['MFSA'] == 'MFSA 2011-32' or link['MFSA'] == 'MFSA 2011-31' or link['MFSA'] == 'MFSA 2011-30'\
                or link['MFSA'] == 'MFSA 2011-29' or link['MFSA'] == 'MFSA 2005-58':
            logging.debug('Пропуск ссылки {} c id:{}, причина пропуска: Ссылки сформированы не в стандартном виде'
                          .format(link['url'], link['MFSA']))
            continue

        if link['MFSA'] == 'MFSA 2009-59' or link['MFSA'] == 'MFSA 2008-42' or link['MFSA'] == 'MFSA 2008-13' \
                or link['MFSA'] == 'MFSA 2006-66' or link['MFSA'] == 'MFSA 2006-07':
            logging.debug('Пропуск ссылки {} c id:{}, причина пропуска: Неизвестна, '
                            'в строке xml.ElementTree(root).write(\'vuln.xml\', encoding=\'utf-8\')'
                           .format(link['url'], link['MFSA']))
            continue
        if link['MFSA'] == "MFSA 2009-01" or link['MFSA'] == "MFSA 2007-02":
            logging.debug('Пропуск ссылки {} c id:{}, причина пропуска: Ссылки сформированы не в стандартном виде, '
                          'пропущен заголовок Description'
                          .format(link['url'], link['MFSA']))
            continue

        if link['MFSA'] == "MFSA 2008-40" or link['MFSA'] == "MFSA 2005-51" or link['MFSA'] == "MFSA 2005-49":
            logging.debug('Пропуск ссылки {} c id:{}, причина пропуска: Ошибка, потом разберусь'
                          .format(link['url'], link['MFSA']))
            continue

        data = parse_update_url(link['url'])
        to_xml(output_path, data)
        bar.update(num)

    logging.debug('\nПрограмма отработала успешно')
    print('Программа отработала успешно')


def test_run():
    year, num = check_db_exsist()
    data = parse_update_url('https://www.mozilla.org/en-US/security/advisories/mfsa2005-12/')
    xml_list = to_xml(data)
    # TODO: Проблемные MFSA: 2011-35 - 2011-29, 2005-58, 2009-59, 2008-42, 2008-13, 2006-66, 2006-07, 2009-01, 2007-02 \
    # 2008-40, 2005-51, 2005-49

# Точка входа в программу
if __name__ == '__main__':
    # test_run()
    run()
