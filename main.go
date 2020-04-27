package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/ciphers/xchacha20poly1305"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

const defaultDestDir = ".scrt"

func main() {
	app := &cli.App{
		Name: "scrt",
		Commands: []*cli.Command{
			{
				Name: "encrypt",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "key",
						Usage: "private key",
						Required: true,
					},
				},
				ArgsUsage: "<path>",
				Action: func(c *cli.Context) error {
					if c.NArg() != 1 {
						return fmt.Errorf("missing argument: <path>")
					}
					srcPath := c.Args().Get(0)
					srcFile, err := os.Open(srcPath)
					if err != nil {
						return err
					}

					srcContent, err := ioutil.ReadAll(srcFile)
					if err != nil {
						return err
					}

					encrypted, err := encrypt(string(srcContent), c.String("key"))
					if err != nil {
						return err
					}

					destPath := filepath.Join(defaultDestDir, filepath.Base(srcPath))
					if err = ioutil.WriteFile(destPath, []byte(srcPath + "\n" + encrypted), 0644); err != nil {
						return err
					}
					return nil
				},
			},

			{
				Name: "decrypt",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "key",
						Usage: "private key",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					files, err := ioutil.ReadDir(defaultDestDir)
					if err != nil {
						return err
					}

					for _, file := range files {
						f, err := os.Open(filepath.Join(defaultDestDir, file.Name()))
						if err != nil {
							return err
						}

						scanner := bufio.NewScanner(f)

						scanner.Scan()
						path := scanner.Text()
						fmt.Println("path", path)

						scanner.Scan()
						encrypted := scanner.Text()
						fmt.Println("decrypted", encrypted)

						decrypted, err := decrypt(encrypted, c.String("key"))
						if err != nil {
							return err
						}

						if err = ioutil.WriteFile(path, []byte(decrypted), 0644); err != nil {
							return err
						}

						if err = f.Close(); err != nil {
							return err
						}
					}
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func encrypt(plainText, secretKey string) (string, error) {
	key, err := symmecrypt.NewKey(xchacha20poly1305.CipherName, secretKey)
	if err != nil {
		return "", err
	}

	encrypted, err := key.Encrypt([]byte(plainText))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func decrypt(encryptedText, secretKey string) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	key, err := symmecrypt.NewKey(xchacha20poly1305.CipherName, secretKey)
	if err != nil {
		return "", err
	}

	decrypted, err := key.Decrypt(encrypted)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}
