package basicauth

import (
	"errors"

	"github.com/gin-gonic/gin"
)

func GetUserFromContext(c *gin.Context) (*User, error) {
	user, exists := c.Get("user")
	if !exists {
		return nil, errors.New("user not found in context")
	}

	authUser, ok := user.(*User)
	if !ok {
		return nil, errors.New("invalid user type in context")
	}

	return authUser, nil
}
