import os

env = Environment()

debug = ARGUMENTS.get('debug', 0)

if int(debug):
	env.Append(CCFLAGS = '-g')

Export('env')

objs = []
cwd  = os.getcwd()
list = os.listdir(cwd)

for item in list:
    if os.path.isfile(os.path.join(cwd, item, 'SConscript')):
        objs = objs + SConscript(os.path.join(item, 'SConscript'))


env.Library('cryptoc',objs)

