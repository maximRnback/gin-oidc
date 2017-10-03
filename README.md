# gin-oidc
gin middleware - an OIDC client for a relying party web server

# example usage

```golang
  //middleware params
 	initParams := gin_oidc.InitParams{
 		Router:       router,
 		ClientId:     "xx-xxx-xxx",
 		ClientSecret: "xx-xxx-xxx",
 		Issuer:       "https://accounts.google.com/", //add '.well-known/openid-configuration' to see it's a good link
 		ClientUrl:    "http://example.domain/", //your website's url
 		Scopes:       ["openid"],
 		ErrorHandler: func(c *gin.Context) {
 			//gin_oidc pushes a new error before any "ErrorHandler" invocation
 			message := c.Errors.Last().Error()
 			//redirect to ErrorEndpoint with error message
 			redirectToErrorPage(c, "http://example2.domain/error", message)
 			//when "ErrorHandler" ends "c.Abort()" is invoked - no further handlers will be invoked
 		},
 		PostLogoutUrl: "http://example2.domain/",
 	}
  
 	//protect all endpoint below this line
 	router.Use(gin_oidc.Init(initParams))
  //or protect a single endpoint
  protectMiddleware := gin_oidc.Init(initParams)
  router.GET("/protectedEndpoint", protectMiddleware, protectedEndpointHandler)
  
```



If you have any questions feel free to open an issue.
