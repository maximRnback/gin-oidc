# gin-oidc
gin middleware - an OIDC client for a relying party web server

# example usage

```golang
  //middleware params
 	initParams := gin_oidc.InitParams{
 		Router:       router,
 		ClientId:     secrets.UsersOidcConfig.ClientId,
 		ClientSecret: secrets.UsersOidcConfig.ClientSecret,
 		Issuer:       *issuer,
 		ClientUrl:    *pgwebUrl,
 		Scopes:       secrets.UsersOidcConfig.Scopes,
 		ErrorHandler: func(c *gin.Context) {
 			//gin_oidc pushes a new error before any "ErrorHandler" invocation
 			message := c.Errors.Last().Error()
 			//redirect to ErrorEndpoint with error message
 			redirectToErrorPage(c, *errorEndpoint, message)
 			//when "ErrorHandler" ends "c.Abort()" is invoked - no further handlers will be invoked
 		},
 		PostLogoutUrl: *postLogoutUrl, // TODO maybe set to '/disconnect'?
 	}
  
 	//protect all endpoint below this line
 	router.Use(gin_oidc.Init(initParams))
  
  //or protect a single endpoint
  protectMiddleware := gin_oidc.Init(initParams)
  router.GET("/protectedEndpoint", protectMiddleware, protectedEndpointHandler)
```



If you have any questions feel free to open an issue.
