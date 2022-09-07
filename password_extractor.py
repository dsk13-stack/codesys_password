"""
Извлечение паролей проекта codesys 2.3

На основании проведенныго анализа был сделан выовод,что
одинаковые проекты с разными паролями имеют разницу в полях в 3-х зонах:
1) по адресу 162h 163h разные сигнатуры, зависящие от некоторых параметров файла
2) в конце файла 4 байта (видимо CRC\контрольная сумма)
3) в конце файла есть поля группового пароля состоящие из :
- метки: Variable_Configuration;
- затем после метки заглушка ff ff ff ff;
- после этого следуют поля с значением (длина + 1) групповых паролей (в моем примере 0B=11, поэтому длина 10 символов);
- затем метка 01h, после этого следует зашифрованный пароль;
- паролей для других групп может быть больше, они разделены символом 01h (проверено для codesys 2.3);
- конец поля пароля помечается подписью cd cd cd cd cd cd cd cd;

Пример:

56 61 72 69 61 62 6c 65 5f 43 6f 6e 66 69 67 75
72 61 74 69 6f 6e 00 00 09 00 00 00 ff ff ff ff
00 00 0b 00 00 00 01 94 97 96 91 90 93 92 9d 9c
95 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 08
00 00 00 00 00 00 cd cd cd cd cd cd cd cd

Где:
0b - длинна пароля
01 - метка начала пароля
94 97 96 91 90 93 92 9d 9c 95 - пароль в закодированом формате

Кодирование пароля заключается в проведении операции XOR A5h на шестнадцатиричном значении символа ASCII.
Соответсвенно для декодирования необходимо провести XOR на каждом байте пароля, для получения его кода в таблице  ASCII

Данный скрипт позволяет извлечь пароли для всех групп непосредствено из файла проекта .pro

"""


PASS_LINE_START_SIGN = b'\x00Variable_Configuration'
START_SIGN_LEN = 35
PASS_LINE_END_SIGN = b'\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd'
DECODING_KEY = 0xA5


def codesys_password_decode(hex_list=list) -> str:
    cracked_password = ""
    for i in hex_list:
        ascii_char = chr(int(i, 16) ^ DECODING_KEY)
        cracked_password += ascii_char
    return cracked_password


def password_line_extract(codesys_file_path):
    hex_password_list = []
    with open(codesys_file_path, "rb") as file:
        data = file.readlines()
        for line_index in range(len(data) - 1, 0, -1):
            if PASS_LINE_END_SIGN in data[line_index] and PASS_LINE_START_SIGN in data[line_index]:
                start_index = data[line_index].index(PASS_LINE_START_SIGN) + START_SIGN_LEN
                end_index = data[line_index].index(PASS_LINE_END_SIGN)
                password_line = data[line_index][start_index:end_index]
                password_line = password_line.hex()
                password_line = str(password_line).replace("00000001", "")
                for byte_index in range(0, len(password_line), 2):
                    hex_password_list.append(password_line[byte_index] + password_line[byte_index + 1])
                break
            elif PASS_LINE_END_SIGN in data[line_index]:
                start_index = 0
                end_index = data[line_index].index(PASS_LINE_END_SIGN)
                raw_data_first = data[line_index][start_index:end_index]
            elif PASS_LINE_START_SIGN in data[line_index]:
                start_index = data[line_index].index(PASS_LINE_START_SIGN) + START_SIGN_LEN
                end_index = len(data[line_index])
                password_line = data[line_index][start_index:end_index] + raw_data_first
                password_line = password_line.hex()
                password_line = str(password_line).replace("00000001", "")
                for byte_index in range(0, len(password_line), 2):
                    hex_password_list.append(password_line[byte_index] + password_line[byte_index + 1])
                break
            else:
                continue
    return hex_password_list


if __name__ == "__main__":

    print("Введите путь к файлу проекта .pro")
    path = input()
    try:
        password_hex_list = password_line_extract(path)
        byte_index = 1
        password = []
        while password_hex_list:
            password_len = int(password_hex_list.pop(0), 16)
            if 1 < password_len <= len(password_hex_list):
                while byte_index < password_len:
                    password.append(password_hex_list.pop(0))
                    byte_index += 1
                print(codesys_password_decode(password))
                password = []
                byte_index = 1
    except Exception as e:
        print(e)
    print("Нажмите Enter для выхода")
    input()









