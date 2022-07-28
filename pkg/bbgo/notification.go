package bbgo

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/spf13/viper"
	"gopkg.in/tucnak/telebot.v2"

	"github.com/c9s/bbgo/pkg/interact"
	"github.com/c9s/bbgo/pkg/notifier/slacknotifier"
	"github.com/c9s/bbgo/pkg/notifier/telegramnotifier"
	"github.com/c9s/bbgo/pkg/service"
	"github.com/c9s/bbgo/pkg/slack/slacklog"
	"github.com/c9s/bbgo/pkg/util"
)

var Notification = &Notifiability{
	SymbolChannelRouter:  NewPatternChannelRouter(nil),
	SessionChannelRouter: NewPatternChannelRouter(nil),
	ObjectChannelRouter:  NewObjectChannelRouter(),
}

func Notify(obj interface{}, args ...interface{}) {
	Notification.Notify(obj, args...)
}

func NotifyTo(channel string, obj interface{}, args ...interface{}) {
	Notification.NotifyTo(channel, obj, args...)
}

type Notifier interface {
	NotifyTo(channel string, obj interface{}, args ...interface{})
	Notify(obj interface{}, args ...interface{})
}

type NullNotifier struct{}

func (n *NullNotifier) NotifyTo(channel string, obj interface{}, args ...interface{}) {}

func (n *NullNotifier) Notify(obj interface{}, args ...interface{}) {}

type Notifiability struct {
	notifiers            []Notifier
	SessionChannelRouter *PatternChannelRouter `json:"-"`
	SymbolChannelRouter  *PatternChannelRouter `json:"-"`
	ObjectChannelRouter  *ObjectChannelRouter  `json:"-"`
}

// RouteSymbol routes symbol name to channel
func (m *Notifiability) RouteSymbol(symbol string) (channel string, ok bool) {
	if m.SymbolChannelRouter != nil {
		return m.SymbolChannelRouter.Route(symbol)
	}
	return "", false
}

// RouteSession routes Session name to channel
func (m *Notifiability) RouteSession(session string) (channel string, ok bool) {
	if m.SessionChannelRouter != nil {
		return m.SessionChannelRouter.Route(session)
	}
	return "", false
}

// RouteObject routes object to channel
func (m *Notifiability) RouteObject(obj interface{}) (channel string, ok bool) {
	if m.ObjectChannelRouter != nil {
		return m.ObjectChannelRouter.Route(obj)
	}
	return "", false
}

// AddNotifier adds the notifier that implements the Notifier interface.
func (m *Notifiability) AddNotifier(notifier Notifier) {
	m.notifiers = append(m.notifiers, notifier)
}

func (m *Notifiability) Notify(obj interface{}, args ...interface{}) {
	if str, ok := obj.(string); ok {
		simpleArgs := util.FilterSimpleArgs(args)
		logrus.Infof(str, simpleArgs...)
	}

	for _, n := range m.notifiers {
		n.Notify(obj, args...)
	}
}

func (m *Notifiability) NotifyTo(channel string, obj interface{}, args ...interface{}) {
	for _, n := range m.notifiers {
		n.NotifyTo(channel, obj, args...)
	}
}


func setupInteraction(persistence service.PersistenceService) error {
	var otpQRCodeImagePath = "otp.png"
	var key *otp.Key
	var keyURL string
	var authStore = getAuthStore(persistence)

	if v, ok := util.GetEnvVarBool("FLUSH_OTP_KEY"); v && ok {
		logrus.Warnf("flushing otp key...")
		if err := authStore.Reset(); err != nil {
			return err
		}
	}

	if err := authStore.Load(&keyURL); err != nil {
		logrus.Warnf("telegram session not found, generating new one-time password key for new telegram session...")

		newKey, err := setupNewOTPKey(otpQRCodeImagePath)
		if err != nil {
			return errors.Wrapf(err, "failed to setup totp (time-based one time password) key")
		}

		key = newKey
		keyURL = key.URL()
		if err := authStore.Save(keyURL); err != nil {
			return err
		}

		printOtpAuthGuide(otpQRCodeImagePath)

	} else if keyURL != "" {
		key, err = otp.NewKeyFromURL(keyURL)
		if err != nil {
			logrus.WithError(err).Errorf("can not load otp key from url: %s, generating new otp key", keyURL)

			newKey, err := setupNewOTPKey(otpQRCodeImagePath)
			if err != nil {
				return errors.Wrapf(err, "failed to setup totp (time-based one time password) key")
			}

			key = newKey
			keyURL = key.URL()
			if err := authStore.Save(keyURL); err != nil {
				return err
			}

			printOtpAuthGuide(otpQRCodeImagePath)
		} else {
			logrus.Infof("otp key loaded: %s", util.MaskKey(key.Secret()))
			printOtpAuthGuide(otpQRCodeImagePath)
		}
	}

	authStrict := false
	authMode := interact.AuthModeToken
	authToken := viper.GetString("telegram-bot-auth-token")

	if authToken != "" && key != nil {
		authStrict = true
	} else if authToken != "" {
		authMode = interact.AuthModeToken
	} else if key != nil {
		authMode = interact.AuthModeOTP
	}

	if authMode == interact.AuthModeToken {
		logrus.Debugf("found interaction auth token, using token mode for authorization...")
		printAuthTokenGuide(authToken)
	}

	interact.AddCustomInteraction(&interact.AuthInteract{
		Strict: authStrict,
		Mode:   authMode,
		Token:  authToken, // can be empty string here
		// pragma: allowlist nextline secret
		OneTimePasswordKey: key, // can be nil here
	})
	return nil
}

func setupSlack(userConfig *Config, slackToken string, persistence service.PersistenceService) {
	conf := userConfig.Notifications.Slack
	if conf == nil {
		return
	}

	if !strings.HasPrefix(slackToken, "xoxb-") {
		logrus.Error("SLACK_BOT_TOKEN must have the prefix \"xoxb-\".")
		return
	}

	// app-level token (for specific api)
	slackAppToken := viper.GetString("slack-app-token")
	if len(slackAppToken) > 0 && !strings.HasPrefix(slackAppToken, "xapp-") {
		logrus.Errorf("SLACK_APP_TOKEN must have the prefix \"xapp-\".")
		return
	}

	if conf.ErrorChannel != "" {
		logrus.Debugf("found slack configured, setting up log hook...")
		logrus.AddHook(slacklog.NewLogHook(slackToken, conf.ErrorChannel))
	}

	logrus.Debugf("adding slack notifier with default channel: %s", conf.DefaultChannel)

	var slackOpts = []slack.Option{
		slack.OptionLog(log.New(os.Stdout, "api: ", log.Lshortfile|log.LstdFlags)),
	}

	if len(slackAppToken) > 0 {
		slackOpts = append(slackOpts, slack.OptionAppLevelToken(slackAppToken))
	}

	if b, ok := util.GetEnvVarBool("DEBUG_SLACK"); ok {
		slackOpts = append(slackOpts, slack.OptionDebug(b))
	}

	var client = slack.New(slackToken, slackOpts...)

	var notifier = slacknotifier.New(client, conf.DefaultChannel)
	Notification.AddNotifier(notifier)

	// allocate a store, so that we can save the chatID for the owner
	var messenger = interact.NewSlack(client)

	var sessions = interact.SlackSessionMap{}
	var sessionStore = persistence.NewStore("bbgo", "slack")
	if err := sessionStore.Load(&sessions); err != nil {

	} else {
		// TODO: this is not necessary for slack, but we should find a way to restore the sessions
		/*
			for _, session := range sessions {
				if session.IsAuthorized() {
					// notifier.AddChat(session.Chat)
				}
			}
			messenger.RestoreSessions(sessions)
			messenger.OnAuthorized(func(userSession *interact.SlackSession) {
				if userSession.IsAuthorized() {
					// notifier.AddChat(userSession.Chat)
				}
			})
		*/
	}

	interact.AddMessenger(messenger)
}

func setupTelegram(userConfig *Config, telegramBotToken string, persistence service.PersistenceService) error {
	tt := strings.Split(telegramBotToken, ":")
	telegramID := tt[0]

	bot, err := telebot.NewBot(telebot.Settings{
		// You can also set custom API URL.
		// If field is empty it equals to "https://api.telegram.org".
		// URL: "http://195.129.111.17:8012",
		Token:  telegramBotToken,
		Poller: &telebot.LongPoller{Timeout: 10 * time.Second},
	})

	if err != nil {
		return err
	}

	var opts []telegramnotifier.Option
	if userConfig.Notifications != nil && userConfig.Notifications.Telegram != nil {
		logrus.Infof("telegram broadcast is enabled")
		opts = append(opts, telegramnotifier.UseBroadcast())
	}

	var notifier = telegramnotifier.New(bot, opts...)
	Notification.AddNotifier(notifier)

	// allocate a store, so that we can save the chatID for the owner
	var messenger = interact.NewTelegram(bot)

	var sessions = interact.TelegramSessionMap{}
	var sessionStore = persistence.NewStore("bbgo", "telegram", telegramID)
	if err := sessionStore.Load(&sessions); err != nil {
		if err != service.ErrPersistenceNotExists {
			logrus.WithError(err).Errorf("unexpected persistence error")
		}
	} else {
		for _, session := range sessions {
			if session.IsAuthorized() {
				notifier.AddChat(session.Chat)
			}
		}

		// you must restore the session after the notifier updates
		messenger.RestoreSessions(sessions)
	}

	messenger.OnAuthorized(func(userSession *interact.TelegramSession) {
		if userSession.IsAuthorized() {
			notifier.AddChat(userSession.Chat)
		}

		logrus.Infof("user session %d got authorized, saving telegram sessions...", userSession.User.ID)
		if err := sessionStore.Save(messenger.Sessions()); err != nil {
			logrus.WithError(err).Errorf("telegram session save error")
		}
	})

	interact.AddMessenger(messenger)
	return nil
}

