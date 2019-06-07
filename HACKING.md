For contributors, we strongly suggest using the following configuration
according to your editors.

## EMACS CONFIGURATION

No change needed. See [.dir-locals.el](.dir-locals.el).

## VIM CONFIGURATION

Please add the following script to the end of your `~/.vimrc`,
or place in `~/.vim/after/ftplugin/c.vim` if you have other plugins.

```
" Checking if the file is cloned from https://github.com/oscarlab/graphene
let GitUrl = system("cd ".expand('%:p:h')."; git config --get remote.origin.url 2>/dev/null")
if GitUrl =~ "oscarlab/graphene"
  " If so, apply the Graphene formatting rules
  set shiftwidth=4
  set tabstop=8
  set expandtab
  set textwidth=100
  set formatoptions=tcq
endif
```

__** Disclaimer: Due to security concerns, we do not suggest using Vim modelines or `.exrc`. **__
