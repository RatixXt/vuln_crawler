import xml.etree.ElementTree as xml
import re
import logging


# Преобразование данных в XML
def to_xml(output_path, data):
    logging.debug('Начался парсинг данных в xml')
    tree = xml.parse(output_path)
    root = tree.getroot()

    for num, vuln in enumerate(data):
        vul = xml.Element('vul')
        identifier = xml.SubElement(vul, 'identifier')
        identifier.text = vuln['id']

        description = xml.SubElement(vul, 'description')
        description.text = vuln['Description']

        vuln_soft = xml.SubElement(vul, 'vulnerable_software')

        for product in vuln['Products']:
            soft = xml.SubElement(vuln_soft, 'soft')
            vendor = xml.SubElement(soft, 'vendor')
            if 'MS' in vuln['id'] or 'ms' in vuln['id']:
                vendor.text = 'Microsoft Corporation'
            elif 'Mozilla' in vuln['id']:
                vendor.text = 'Mozilla Foundation'
            else:
                logging.critical('Для уязвимости с id {} не найден вендор'.format(vuln['id']))
                vendor.text = '.'
            name = xml.SubElement(soft, 'name')
            name.text = product
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

            elif re.search('Windows', product):
                type_.text = 'ОС'
                enviroment = xml.SubElement(vul, 'enviroment')
                os_ = xml.SubElement(enviroment, 'os')
                vendor = xml.SubElement(os_, 'vendor')
                vendor.text = 'Windows Corp.'
                name = xml.SubElement(os_, 'name')
                name.text = product
                version = xml.SubElement(os_, 'version')
                version.text = product
                platform = xml.SubElement(os_, 'platform')

                if re.search('x64', product):
                    platform.text = 'x64'
                else:
                    platform.text = 'x86'

            # TODO Добавить продукты MS
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

        # Не совсем верно, но дата обнаружения будет ставиться как дата исправления
        identify_date = xml.SubElement(vul, 'identify_date')
        identify_date.text = vuln['Announced']

        cvss = xml.SubElement(vul, 'cvss')
        vector = xml.SubElement(cvss, 'vector')
        vector.text = '.'

        severity = xml.SubElement(vul, 'severity')
        severity.text = vuln['Impact']

        solution = xml.SubElement(vul, 'solution')
        if vuln.get('Workaround') is not None:
            solution.text = vuln['Workaround']
        elif vendor.text == 'Mozilla Foundation':
            solution.text = 'Обновить версию ПО до {}'.format(', '.join(vuln['Fixed in']))
        else:
            solution.text = '.'

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
        root.insert(0, vul)
    try:
        xml.ElementTree(root).write(output_path, encoding='utf-8')
    except Exception as err:
        logging.error("Произошла неизвестная ошибка: {}".format(err))

    logging.debug('Парсинг данных в xml успешно завершен')

