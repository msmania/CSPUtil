GTEST=D:\git\googletest

!IF "$(PLATFORM)"=="X64" || "$(PLATFORM)"=="x64"
ARCH=amd64
O_GTEST=$(GTEST)\build64\googlemock\gtest\Release
O_GMOCK=$(GTEST)\build64\googlemock\Release
!ELSE
ARCH=x86
O_GTEST=$(GTEST)\build32\googlemock\gtest\Release
O_GMOCK=$(GTEST)\build32\googlemock\Release
!ENDIF

OUTDIR=$(ARCH)
OBJDIR=$(ARCH)

CC=cl
RD=rd /s /q
RM=del /q
LINKER=link
TARGET=t.exe

OBJS=\
	$(OBJDIR)\blob-test.obj\

LIBS=\
	advapi32.lib\
	crypt32.lib\
	gdi32.lib\
	..\src\$(ARCH)\common.lib\
	gtest.lib\
	gtest_main.lib\

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
	/I..\src\common\
	/I$(GTEST)\googlemock\include\
	/I$(GTEST)\googletest\include\

LFLAGS=\
	/NOLOGO\
	/DEBUG\
	/SUBSYSTEM:CONSOLE\
	/LIBPATH:$(O_GTEST)\
	/LIBPATH:$(O_GMOCK)\

all: $(OUTDIR)\$(TARGET)

$(OUTDIR)\$(TARGET): $(OBJS)
	@if not exist $(OUTDIR) mkdir $(OUTDIR)
	@if not exist ..\src\$(ARCH)\common.lib\
		@pushd ..\src\common & nmake /nologo & popd
	$(LINKER) $(LFLAGS) $(LIBS) /PDB:"$(@R).pdb" /OUT:$@ $**

.cpp{$(OBJDIR)}.obj:
	@if not exist $(OBJDIR) mkdir $(OBJDIR)
	$(CC) $(CFLAGS) $<

clean:
	@if exist $(OBJDIR) $(RD) $(OBJDIR)
