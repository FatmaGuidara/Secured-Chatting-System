from string import ascii_lowercase


for c in ascii_lowercase:
    for c_2 in ascii_lowercase:
        file = open("test.txt", "a")
        L = f"{c}.{c_2}@insat.ucar.tn\n"
        file.writelines(L)
        file.close()
# L = f"a.a@insat.ucar.tn"
# file.writelines(L)
