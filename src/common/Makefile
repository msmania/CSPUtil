!IF "$(PLATFORM)"=="X64" || "$(PLATFORM)"=="x64"
ARCH=amd64
!ELSE
ARCH=x86
!ENDIF

OBJDIR=$(ARCH)
OUTDIR=..\$(ARCH)

CC=cl
RD=rd /s /q
RM=del /q
TARGET=common.lib

OBJS=\
	$(OBJDIR)\blob.obj\
	$(OBJDIR)\csp.obj\
	$(OBJDIR)\hash.obj\
	$(OBJDIR)\key.obj\

LIBS=\

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

all: $(OUTDIR)\$(TARGET)

$(OUTDIR)\$(TARGET): $(OBJS)
	@if not exist $(OUTDIR) mkdir $(OUTDIR)
	lib /NOLOGO /OUT:$@ $**

.cpp{$(ARCH)}.obj:
	@if not exist $(OBJDIR) mkdir $(OBJDIR)
	$(CC) $(CFLAGS) $<

clean:
	@if exist $(OBJDIR) $(RD) $(OBJDIR)
	@if exist $(OUTDIR)\$(TARGET) $(RM) $(OUTDIR)\$(TARGET)
