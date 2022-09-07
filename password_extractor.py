PASS_LINE_START_SIGN = b'\x00Variable_Configuration'
START_SIGN_LEN = 35
PASS_LINE_END_SIGN = b'\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd'
DECODING_KEY = 0xA5
PASSWORD_PREFIX = "00000001"


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
                password_line = str(password_line).replace(PASSWORD_PREFIX, "")
                for byte_index in range(0, len(password_line), 2):
                    hex_password_list.append(password_line[byte_index] + password_line[byte_index + 1])
                break
            elif PASS_LINE_END_SIGN in data[line_index]:
                start_index = 0
                end_index = data[line_index].index(PASS_LINE_END_SIGN)
                second_password_line = data[line_index][start_index:end_index]
            elif PASS_LINE_START_SIGN in data[line_index]:
                start_index = data[line_index].index(PASS_LINE_START_SIGN) + START_SIGN_LEN
                end_index = len(data[line_index])
                password_line = data[line_index][start_index:end_index] + second_password_line
                password_line = password_line.hex()
                password_line = str(password_line).replace(PASSWORD_PREFIX, "")
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
