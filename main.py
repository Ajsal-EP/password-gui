from tkinter import *
from tkinter import messagebox

root=Tk()
root.title('Login')
root.geometry('952x500+300+200')
root.configure(bg="#fff")
root.resizable(False,False)
def signin():
    password=code.get()

    if password=='4602':
        screen=Toplevel(root)
        screen.title("App")
        screen.geometry('925x500+300+200')
        screen.config(bg= "white")

        Label(screen,text= 'Say My Name!',bg='#fff',font=('Calibri(Body)',50, 'bold')).pack(expand=True)

        screen.mainloop()

    elif password!='4602':
        messagebox.showerror("Dzamn","Wrong Answer Lil Guy")

img = PhotoImage(file='ahagui.png')
Label(root,image=img,bg='white').place(x=-560,y=-200)

frame=Frame(root,width=350,height=350,bg="white")
frame.place(x=480,y=70)

heading=Label(frame, text= 'SIGN IN',fg='#5D3FD3',bg='white', font= ('Avenir' ,23, 'bold'))
heading.place(x=118,y=15)
#-----------------------------------
user = Label(frame, text='MASTER KEY', width=25, fg='black', border=0,bg="white", font=('verdana',14))
user.place(x=26,y=100)
#Frame(frame,width=295,height=2,bg='black').place(x=25,y=107)
#-----------------------------------
def on_enter(e):
    code.delete(0,'end')

def on_leave(e):
    name=code.get()
    if name=='':
        code.insert(0,'Passkey')
code = Entry(frame, width=25, fg='black', border=0,bg="white", font=('Microsoft YaHei UI Light',11))
code.place(x=30,y=150)
code.insert(0,'Password')
code.bind('<FocusIn>', on_enter)
code.bind('<FocusOut>', on_leave)

Frame(frame,width=295,height=2,bg='black').place(x=25,y=177)

####################################
Button(frame,width=39, pady=7, text='Sign in',bg='#5D3FD3',fg= 'white',border=0,command=signin).place (x=35, y=204)
label=Label(frame, text= "Don't have an account?", fg='black' ,bg='white',font=('Microsoft YaHei UI Light' ,9))
label.place(x=75,y=270)

sign_up=Button(frame,width=6,text='Sign Up',border=0,bg='white',cursor='hand2',fg='#5D3FD3')
sign_up.place(x=215,y=270)


root.mainloop()