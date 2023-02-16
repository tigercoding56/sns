# scan 'n' search!
# author: Sydney Wells
# description: this program uses nmap to scan a target, and returns the services found on the
# target and vulnerabilities of those services if applicable

# imports
import os
import nmap
from mitrecve import crawler

# vuln_search(): runs the name of a program/service through the mitre cve database
# and returns any vulnerabilities associated with it
def vuln_search(name):
    vuln_info = crawler.get_cve_detail(name)
    if len(vuln_info) == 0: # if serach returned no results
        print("No vulnerabilities found. Please perform a manual search.\n")
    else:
        print("Vulnerability Details:")

        # if len(vuln_info) <= 5, print all items
        if len(vuln_info) <= 5:
            for vuln in vuln_info:
                print(f'''{vuln[0]}:\n\nDescription: {vuln[1]}Link: {vuln[2]}''')
        else: # else, print first 5 items
            for i in range(5):
                print(f'''{vuln_info[i][0]}:\n\nDescription: {vuln_info[i][1]}Link: {vuln_info[i][2]}\n\n''')
    print('--\n')


# output_vuln_search(): allows user to save the results to
# a specified output file
def output_vuln_search(f, name):
    vuln_info = crawler.get_cve_detail(name)
    if len(vuln_info) == 0: # if serach returned no results
        f.write("No vulnerabilities found. Please perform a manual search.\n")
    else:
        f.write("Vulnerability Details:")

        # if len(vuln_info) <= 5, print all items
        if len(vuln_info) <= 5:
            for vuln in vuln_info:
                f.write(f'''{vuln[0]}:\n\nDescription: {vuln[1]}Link: {vuln[2]}''')
        else: # else, print first 5 items
            for i in range(5):
                f.write(f'''{vuln_info[i][0]}:\n\nDescription: {vuln_info[i][1]}Link: {vuln_info[i][2]}\n\n''')
    f.write('--\n')


def save_to_file(outfile, target, scan_info, port_list):
    with open(outfile, 'w') as f:
        # print the scanning results
        f.write('Scan Results:\n')
        for port in port_list:
            if (scan_info['scan'][target]['tcp'][port]['product']) == '':
                scan_info['scan'][target]['tcp'][port]['product'] = 'Product name unavailable'
                f.write(f'''Port: {port}\nService: {scan_info['scan'][target]['tcp'][port]['name']}\nProduct: {scan_info['scan'][target]['tcp'][port]['product']}\nVersion: {scan_info['scan'][target]['tcp'][port]['version']}\n\n''')
                # output vulnerability info
                output_vuln_search(f, scan_info['scan'][target]['tcp'][port]['name'])
            elif (scan_info['scan'][target]['tcp'][port]['version']) == '':
                scan_info['scan'][target]['tcp'][port]['version'] = 'Version unavailable'
                f.write(f'''Port: {port}\nService: {scan_info['scan'][target]['tcp'][port]['name']}\nProduct: {scan_info['scan'][target]['tcp'][port]['product']}\nVersion: {scan_info['scan'][target]['tcp'][port]['version']}\n\n''')
                # output vulnerability info
                output_vuln_search(f, scan_info['scan'][target]['tcp'][port]['name'])
            else:
                f.write(f'''Port: {port}\nService: {scan_info['scan'][target]['tcp'][port]['name']}\nProduct: {scan_info['scan'][target]['tcp'][port]['product']}\nVersion: {scan_info['scan'][target]['tcp'][port]['version']}\n\n''')
                # output vulnerability info
                output_vuln_search(f, scan_info['scan'][target]['tcp'][port]['name'])


# # set up the scanner
# nm = nmap.PortScanner()

# # do a lil scanning
# scan_info = nm.scan('127.0.0.1', '21-443')

# # get a list of the ports we have info for
# port_list = list(scan_info['scan']['127.0.0.1']['tcp'].keys())

def print_results(target, scan_info, port_list):
    # print the scanning results
    print('Scan Results:\n')
    for port in port_list:
        if (scan_info['scan'][target]['tcp'][port]['product']) == '':
            scan_info['scan'][target]['tcp'][port]['product'] = 'Product name unavailable'
            print(f'''Port: {port}\nService: {scan_info['scan'][target]['tcp'][port]['name']}\nProduct: {scan_info['scan'][target]['tcp'][port]['product']}\nVersion: {scan_info['scan'][target]['tcp'][port]['version']}\n\n''')
            # output vulnerability info
            print('\nSearching for vulnerabilities...')
            vuln_search(scan_info['scan'][target]['tcp'][port]['name'])
        elif (scan_info['scan'][target]['tcp'][port]['version']) == '':
            scan_info['scan'][target]['tcp'][port]['version'] = 'Version unavailable'
            print(f'''Port: {port}\nService: {scan_info['scan'][target]['tcp'][port]['name']}\nProduct: {scan_info['scan'][target]['tcp'][port]['product']}\nVersion: {scan_info['scan'][target]['tcp'][port]['version']}\n\n''')
            # output vulnerability info
            print('\nSearching for vulnerabilities...')
            vuln_search(scan_info['scan'][target]['tcp'][port]['product'])
        else:
            print(f'''Port: {port}\nService: {scan_info['scan'][target]['tcp'][port]['name']}\nProduct: {scan_info['scan'][target]['tcp'][port]['product']}\nVersion: {scan_info['scan'][target]['tcp'][port]['version']}\n\n''')
            # output vulnerability info
            print('\nSearching for vulnerabilities...')
            vuln_search(scan_info['scan'][target]['tcp'][port]['product'])




# # welcome message
# print("Welcome to Scan'n'Search!\nWould you like to scan a single host or multiple?")

# scan_mode = input("1) Single\n2) Multiple\nq) Quit\n> ")

# while (scan_mode != 'q'):
#     if scan_mode == '1':
#         # ask for target
#         host = input("Enter target (ex. 127.0.0.1 or scanme.nmap.org)> ")
#         print("\nBeginning scan...\n")

#         # set up the scanner
#         nm = nmap.PortScanner()

#         # do a lil scanning
#         scan_info = nm.scan(host, '21-443')

#         # get a list of the ports we have info for
#         temp = list(scan_info['scan'].keys())
#         target = temp[0]
#         port_list = list(scan_info['scan'][target]['tcp'].keys())

#         term_or_file = input("Where would you like your results output?\n\n1) Output to terminal\n2) Output to file\n> ")
#         if term_or_file == '2':
#             outfile = input("Name your output file (please include '.txt')> ")
#             print("Saving output to file...")
#             save_to_file(outfile, target, scan_info, port_list)
#             print(f"Success! Output file saved to {outfile}\n")

#         else:
#             print_results(target, scan_info, port_list)

#     elif scan_mode == '2':
#         print("\nComing soon!\n")
#     else:
#         print("\nInvalid input! Try again.\n")
#     scan_mode = input("1) Single\n2) Multiple\nq) Quit\n> ")

# # user has pressed quit
# print("\nThanks for using Scan'n'Search. Goodbye!")
# input()

host = input("what host would you like to scan ? :")
# set up the scanner
nm = nmap.PortScanner()
# do a lil scanning
scan_info = nm.scan(host, '80-443')

# get a list of the ports we have info for
temp = list(scan_info['scan'].keys())
target = temp[0]
print(target)
port_list = list(scan_info['scan'][target]['tcp'].keys())
print(port_list)

print_results(target, scan_info, port_list)
