import requests
import bs4
from datetime import datetime
import re
import logging
import progressbar
from functions import *

__author__ = 'Aleksei Shcherbakov'
__version__ = '0.02'

PROXIES = dict()

# Настройка логера
logging.basicConfig(format=u'%(levelname)-8s [%(asctime)s] %(message)s', level=logging.DEBUG, filename=u'log.log')


# Функция находит ссылки на информацию об обновлениях безопасности с блога Mozilla
# Блог https://www.mozilla.org/en-US/security/advisories/
# url - ссылка на информацию об обновлении
# MFSA - id обновления безопасности от Mozilla
def get_update_urls(year=0, num=0):
    domain = 'https://www.mozilla.org/'
    blog_url = 'https://www.mozilla.org/en-US/security/advisories/'
    html_str = requests.get(blog_url, proxies=PROXIES).content
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
                urls.append({'url': '{}{}'.format(domain, tag.get('href')), 'id': tag.contents[0].contents[0]})

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
    html_str = requests.get(url, proxies=PROXIES).content
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

    vuln_info['id'] = soup.header.h1.contents[0]
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

        # Изменения для передачи в функцию формирования xml
        vuln_info['Products'] = vuln_info['Products'].split(', ')
        vuln_info['Announced'] = datetime.strptime(vuln_info['Announced'], "%B %d, %Y").strftime('%d.%m.%Y')

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

            # Изменения для передачи в функцию формирования xml
            vuln_info['Products'] = vuln_info['Products'].split(', ')
            vuln_info['Announced'] = datetime.strptime(vuln_info['Announced'], "%B %d, %Y").strftime('%d.%m.%Y')

            list_vuln_info.append(vuln_info)
    logging.debug('Парсинг URL успешно закончен')

    return list_vuln_info


def run_mf_parsing(proxy, output_path, year, num):

    if proxy is not None:
        PROXIES['http'] = proxy
        PROXIES['https'] = proxy

    links = get_update_urls(year, num)
    links.reverse()

    # Пропуски
    bar = progressbar.ProgressBar(max_value=len(links))

    if not links:
        logging.info('База уязвимостей в актуальном состоянии')
        print('База уязвимостей в актуальном состоянии')

    for num, link in enumerate(links):
        if int(re.search('(\d+)\-', link['id']).group(1)) < 2017:
            continue

        # Все условия пропускают ссылки, которые парсятся с ошибками
        if link['id'] == 'MFSA 2011-35' or link['id'] == 'MFSA 2011-34' or link['id'] == 'MFSA 2011-33' \
                or link['id'] == 'MFSA 2011-32' or link['id'] == 'MFSA 2011-31' or link['id'] == 'MFSA 2011-30' \
                or link['id'] == 'MFSA 2011-29' or link['id'] == 'MFSA 2005-58' or link['id'] == 'MFSA 2006-68':
            logging.debug('Пропуск ссылки {} c id:{}, причина пропуска: Ссылки сформированы не в стандартном виде'
                          .format(link['url'], link['id']))
            continue

        if link['id'] == 'MFSA 2009-59' or link['id'] == 'MFSA 2008-42' or link['id'] == 'MFSA 2008-13' \
                or link['id'] == 'MFSA 2006-66' or link['id'] == 'MFSA 2006-07':
            logging.debug('Пропуск ссылки {} c id:{}, причина пропуска: Неизвестна, '
                          'в строке xml.ElementTree(root).write(\'vuln.xml\', encoding=\'utf-8\')'
                          .format(link['url'], link['id']))
            continue
        if link['id'] == "MFSA 2009-01" or link['id'] == "MFSA 2007-02":
            logging.debug('Пропуск ссылки {} c id:{}, причина пропуска: Ссылки сформированы не в стандартном виде, '
                          'пропущен заголовок Description'
                          .format(link['url'], link['id']))
            continue

        if link['id'] == "MFSA 2008-40" or link['id'] == "MFSA 2005-51" or link['id'] == "MFSA 2005-49":
            logging.debug('Пропуск ссылки {} c id:{}, причина пропуска: Ошибка, потом разберусь'
                          .format(link['url'], link['id']))
            continue

        data = parse_update_url(link['url'])
        to_xml(output_path, data)
        bar.update(num)

