fmt:
	go fmt ./...

	go build ./...

export_static:
	fyne bundle -name ECDSAKey -package data 