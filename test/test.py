#from includes.single_ip import ip_info
#from includes.ip_file import process_ip_list

import sys
sys.path.append('C:\\Users\\d.lekontsev\\Documents\\Development\\Test_IP_check_bot')


from includes.ip_list import extract_and_validate, check_ip_list


# Пример использования
text_with_ips = "213.87.14.102 \
104.255.66.139 \
urler.site \
localzilla.fun \
sensor.fun \
574056cm.nyashka.top\
    xxxxagl;bfxcbadfq34 gasdljvpzoj apwhsfdpsahnpxzska as;da"
result = check_ip_list(text_with_ips)
print(result)


'''
test = ip_info('193.124.92.111')
print(test)

file_path = input("Type the input file (Example: input.txt): ")
process_ip_list(file_path)
'''
