original = open("rr.txt","r")
sent = open("recv/rr.txt","r")

print(original.read()==sent.read())
original.close()
sent.close()

"101751.209091ms"