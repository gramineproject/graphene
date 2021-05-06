foreach script : [
    'get-python-platlib.py',
]
    set_variable('@0@_prog'.format(script.split('.')[0].underscorify()),
        find_program(script))
endforeach
