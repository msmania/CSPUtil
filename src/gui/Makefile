!IF "$(PLATFORM)"=="X64" || "$(PLATFORM)"=="x64"
OUTDIR=..\..\bin64
OBJDIR=obj64
ARCH=amd64
!ELSE
OUTDIR=..\..\bin32
OBJDIR=obj32
ARCH=x86
!ENDIF

CC=cl
LINKER=link
TARGET=gui.exe

OBJS=\
	$(OBJDIR)\blob.obj\
	$(OBJDIR)\csp.obj\
	$(OBJDIR)\hash.obj\
	$(OBJDIR)\key.obj\
	$(OBJDIR)\main.obj\
	$(OBJDIR)\gui.res\

LIBS=\
	advapi32.lib\
	crypt32.lib\
	gdi32.lib\

CFLAGS=\
	/nologo\
	/c\
	/DUNICODE\
	/O2\
	/W4\
	/Zi\
	/EHsc\
	/Fo"$(OBJDIR)\\"\
	/Fd"$(OBJDIR)\\"\

LFLAGS=\
	/NOLOGO\
	/DEBUG\
	/SUBSYSTEM:WINDOWS\

all: $(OUTDIR)\$(TARGET)

$(OUTDIR)\$(TARGET): $(OBJS)
	@if not exist $(OUTDIR) mkdir $(OUTDIR)
	$(LINKER) $(LFLAGS) $(LIBS) /PDB:"$(@R).pdb" /OUT:$@ $**

{.\}.cpp{$(OBJDIR)}.obj:
	@if not exist $(OBJDIR) mkdir $(OBJDIR)
	$(CC) $(CFLAGS) $<

{..\common\}.cpp{$(OBJDIR)}.obj:
	@if not exist $(OBJDIR) mkdir $(OBJDIR)
	$(CC) $(CFLAGS) $<

{.\}.rc{$(OBJDIR)}.res:
	@if not exist $(OBJDIR) mkdir $(OBJDIR)
	rc /nologo /fo "$@" $<
