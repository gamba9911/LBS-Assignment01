assignment.pdf: *.tex literature.bib
	latexmk -pdf assignment.tex
pvc-force:
	latexmk --pvc --synctex=1 -f --quiet assignment.tex -pdf
clear:
	rm *.aux *.bbl *.blg *.fls *.dvi *.fdb_latexmk *.log *.out *.synctex.gz assignment.pdf
