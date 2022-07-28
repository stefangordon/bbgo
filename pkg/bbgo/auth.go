package bbgo

import (
	"fmt"

	"github.com/c9s/bbgo/pkg/service"
)

func getAuthStore(persistence service.PersistenceService) service.Store {
	id := getAuthStoreID()
	return persistence.NewStore("bbgo", "auth", id)
}

func printAuthTokenGuide(token string) {
	fmt.Printf(`
For telegram, send the following command to the bbgo bot you created to enable the notification:

	/auth

And then enter your token

	%s

`, token)
}
