module example.com/fx

go 1.21

require (
	github.com/gin-gonic/gin v1.6.0
	golang.org/x/text v0.3.0 // indirect
	example.com/local v1.0.0
)

require golang.org/x/net v0.0.0-20200202094626-16171245cfb2 // indirect

replace example.com/local => ../local
