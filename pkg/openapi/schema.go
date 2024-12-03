// Package openapi provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
package openapi

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	externalRef0 "github.com/unikorn-cloud/core/pkg/openapi"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"H4sIAAAAAAAC/+y9aXPiOtsg/FdcvFN1ZqogzR7oL/MQtkDCvnOnX0q2BQhs2bFkwHT1f5+SZIMNhpB0",
	"n77Pkk/ndJC1XLr2Td8jiqGbBoaYksjX7xETWECHFFr8XwvLsE2ktr0/sr+pkCgWMikycORrpCDZGL3a",
	"UOJDpVrpLhKNIPaLCegyEo1goMPIV2+mSDRiwVcbWVCNfKWWDaMRoiyhDtjM1DHZUEIthBeRHz+iEQPY",
	"dJlsW8ZGhVatdG0fWBKDJdMyNkiF1uW9eCNqpfdux1oAjPaArfnmbnxjL28lOOM7t2Naxgoq9PpOJHfU",
	"VXCIad61/A8xGBL6YKgIcnRRLAgorLKr7orf+F8NTCHm/wtMU0MKP+2XFWEb/O5b4n9ZcB75Gvn/vhxR",
	"8ov4lXzh+DOyEIVi7eApHwzVkby9S9SQxE4kINDy7uxkP6LuZtvi8LdvF+6AbmqQ/a8OKVAB5Xt3Yak7",
	"MReckR/RCDGhciAjEvn6n4iqqjCbh/OYLGeSsXQukYnlYR7GAFRzmaySjWfu55Fv7IC3gcVd7CJg3ONJ",
	"7lVJR/IOhYlmLBB+Gxa72Ha7jc0NS4/ZlgaxYqhskgBwoA6QFvkaWRnwTtaMxYL8D1B0eKcYeiQaIRRQ",
	"Bi/o1JdyVUEtVK8N9rVEE9VIDXczSrGWra3N8bBYz99Bp75XRzXUQrVdY9WIN/uTVKu03tbQFsl6hU57",
	"fPAGVNOLbjWvsb+DUSVeWxm7Zr+cbKwamUap5sw7d7259rTbduu9Bnx6qiQ7/fR8azZgfZ7KtlvrrFMf",
	"zoDaIWSbUSI3X4Ifai0OeRJ2FzXMICYYAoYKJARYDkNWCxJD2zBsnUMVWoBCVer1WgdOFnpVR9bIhvxq",
	"cgvO/n66O+PGoWegxhr+InRTNAQxnSGVIVUmp6bzcRjLJue5WDoPUjH5Xo3H5LwM5WwiowJZjkQjbJog",
	"ClY68W7teTDsMwyapLqZ2spAPU0dsH9PR5kV+3enX0s012qp36uRmj7cAqeWhU7dUh/XYg6H/b3pqKiW",
	"rWkF2uzXdux7yFG6gpR4ZjlIPDiT1CTTHdbJSK9YrcdhSUkO4/1kJQn69bTcS1AwrrRHq+Gmo1ea3aRJ",
	"lXimKKN4GpRz6c4gX5Kr3WRr2EipJc1R+w9lubQE8r5SVvrLXavcyIwGZnxUrc9BfIKei3V+ls5okBr2",
	"EiVlTckk1a23xpN9I94l/VGF9OLTh+k6P1GKiQ4c5vfT+CTTX6kAxDPNzrpb6q6HT3K8YnWdRKWPl31l",
	"X0s2yhkd6ot0D9dxDz905UGlMnpcbqZx0xg9msnJaNro9Or552LdAqMOp+Dp4zKlJPNPA21a7ui7/kTf",
	"bXp6np2j3l/Xt2q13peTifFAe5gq68wzHDUrnWG+y2CoPmrbw53g+N2dbXV1efeYnMk499zQwN1kGwep",
	"V0IfG4UnvAPbdW2C6aOyaRVXYLfab4aJuqZPGrFksS8XEyg5pAXSrD0ZLa1Sz2Qfk814zmxM8i1zmlTs",
	"dfGxnXjo7MhTgyjpxHCr1aaTzapi7Ue1MiwZlXyyopvFbnW0p/ZWWT6M1Pt2uTMx57BeqScf4AIo1SXs",
	"vM6743Eq022WnNi0paTV0dreVKxhrtazC7nY/UyB948gmelZXbvXBVZ/3pg9PBcSdqkwa+cLo9WSONWn",
	"1lOysrZBaRAf62PteVTaZ9Un9cnJd+u0O8ODgUK0FQU1vT5eNZvtgl5/TcRxPRNPlJ9mtWwj/5DqdwfW",
	"K9BaD3p6Te5jG70yWyjlBAGtTbKgoHK+nXxorJVsKrMGpVQx86g5o34+01ur2eKssjXNVWewmQwmcee+",
	"/Jpsmng4X4/Tdq+t5+aDUlq2eqvqCD82muXcPt1IztpaI/3UmxYQfO7qjcJqktmNcuPJzC6OrQyWY7me",
	"Xpi1Y9qqOGy124VxaVzegeSut5ML9Y01eR1Bu5qsbQrrYhzIWdNYaa8Dfd0dbVrjDMXjDthkNq3ka6uw",
	"KE4Gy15tNN7HY5PcUtl3B71Fqe909EzeGdzvXoevReRsi8vFWGulkk/b5RJb8+ddU7MaD+nMuKXtl/V2",
	"QkmViov76ehebs0694V4rrraWONdX79fDEpWbEXUUX7Z76FmvWPPZvteo9IeDpv9V7xPNEqVGrQJylbr",
	"KD8sxgszwx4Tdak0n3B2BWulYV7FjV1RWcmdfuaVFMuvRmygFKubx/hsmwbFpampjUXusdqGg950CR56",
	"zwkHk1ktXswXCqUKzKv6uJndFh8f7Fy96MT66YoBx11t2Hsa2tVktY5yZL4vVCrLLHpadsa7Rz3z1CzM",
	"kGE91IflVm+cUp+zT63BeK6Sh3l/v0iBhlF2zKRczzcBUGhVrzj1aSMPs41dLzfYLZrZp0d4X1VtJd6s",
	"VpwHy04VtcZr8mGvLFs7eV/qzAyUmRg9e/dsLqpaaofq8yYuaq+V/uu4Ub/P2L11fNZaPy02+iME+U61",
	"CwDZZcaF554JzJmyLk43zcmqOjOmy3Q8HXvqr0yQRPVFuans4aCfrKRXr5m8VSwWBpXpcO7YqVf6UIB1",
	"HaaHiyWW+xtQ69dlswIfBk5vMXlS7Grnzt50GiukDVCurqhOFaaeZUAXLtOfbaCF5oipy5HpqBNvVOur",
	"aXXiNPvL9bQ0cRrJzra57zit/iTerDbi09F01dgPMtNVV2+U1vvparhulurr5mq4bK4Ku2lpsp/2h+vJ",
	"fhJv6M3VtGNEopGFBTCduWozE4aG5Sr6My55mDxUkQUVOrMtFPkaWVJqkq9fvrhSjWlKrhz+ogBNk4Gy",
	"vl0n8YvWKzpJq8ClNB/tKYlRSTEwsTUq0SWULKjBDcBUcocCrEqtWqkoMeUWzV0ZTaS5YUlz26JLaEkq",
	"pABp4Sqmbap/ERtB7OSqjSCGtHxG2i9XtHxzv3/rQTPzyhE+zZwjTLjlSkwDE2G1AkXruv9+H2D8sOc/",
	"YdU0EHek/Od7wPFBItGIYTLVnhPi1/+41iffHFAj3jVF2ME0SGHk249v0QjXZoEqJ2E6kY4lAJzH0plc",
	"PibnU6kYUOPZREpNqve5eeToDeBrh+4E4bkFCLVshdoWvLQj38K5bBaCeCaWzGYysXRCVmK5RCoTU/N5",
	"OZuEalqG2ciPbzdfIlC0sLsrSBoiVDLmElCYUcS4D7UMxj5+RIOM88I1UbijX5ZU1yJfv4fOz+wzxqB0",
	"YW0JHHFtLWaNMeyW5pahc45nE2ausLU3AGlA1gS3Ih9Bkv98j6iImBpwmuISCqqOMCLUAtSwyIl/jHwx",
	"dMdQHo2qBc0lA+7NsA1uNRzOB8+Y8NUhzI8b5CA/omIrH6MIP6vg+IQM3Ef8gMl4Mh2LZ2KpRD+R/ppI",
	"fI3HpxEP0xLp5DybTsTu52o2lgZyPgZy95lYKp1W7qEMVCWTOoIKxCgEeuTEHcfmUdPZeFzNwhjMZzOx",
	"tJxOx0Aunovl0nM5OQep7H08GYkK/x9BBkZ40aOA2sRzCrI/QtXP0yxDg7WSYGq3zP4tGmH4wz+YAwX+",
	"j9gtd3u8g+G5dwDU8Ju84QI/iq6fV/jGFX571x2S6yxPjOHKU+hVMq5WtizD+iDrW0AMLaRIj/3GswTZ",
	"RJIJFpDPvdquycfIfA0dIVkUa8OkbyyTTESikTXHhIS62xKj3h2WHrSerBl1Y0vzteaDSeWeoY+67YnV",
	"fHKUcmHWYd9QJ/I1Ui5GONAjXyMEMTV9x3ZfHRVk++kB4/jrmKxySFVHy+kqE5v2G+lKWs1Ydfgky1qr",
	"OlRiGVxvDrqkLd+vY41l+dXKdwoos3rC6r221tePg6SOgbYlnfZTJBphaxYK0Cxqo16uYTw/F/evjU5S",
	"1lJP233lHvYmz0ulZ5F1bj2xu6DZTGd0PLQ75DGd6rRqz+WHzHgMHpdOr9ddDItAb2yno8G2YG0S6/eI",
	"RAbbEZSfoNODNBxT6r1WU9pCWVpDRyKQ3kn9JSISIhJg/2RIxIhKlUxb1pDChhGJLgGVgMW09zm0IFag",
	"KskOn+sFs8m4wk/YXND3oaQALMlcAnI1k9tJjjubayRsAZEIWmAxI10i8oIJtDZIEVh16pf8y4qRhWEs",
	"NBhDKsQUUec3MSPhp6yVGKEkEvFsPpXKZbPpmGkocSWXUBdkbqtW3JJtcxW3sW2tlA1NJOEdME1yJ/bM",
	"uJMLTNedjgixuTnr2ZBAUQwbU+8LPux26XN6hxfEUIiT9wwB/tJi6F+IAt8+hgNviLETPBCqu2FCjNSi",
	"gedoYVvXFPifMJ/P1wh1c5gQ10rMsjiOE1yOSV5gUyOmIqIYG2g57DwH+4m7O4htmoZFofqCgbYwLESX",
	"uvhlDgGzpdzzBtwEf131WdFhTDEs851oqxo64NFjN4zHJ/CfuS9cXe64qD/M/jUiZ6GSTCfUGEzJ6Vga",
	"zJUYuAcglonH54qczcTVHHwPhwrA+jJ/OtWn/H/4a2vIf+Vb+vaRa3qLhfiH3klSwyCUm+JEIkvD1lTJ",
	"wBrTgKBkYBhlRAktCTBzmjC9hWkhUAKaFpxJMoSRZGqAzg1Lv/O5Sv7CROpzsP0eoXT03cF5Jp5X1ERM",
	"uYfZWDo5z8UAgPcxEE8ksmlVycZV5QO+u8vGrDvAfzN/adL8G9zNt3dezhu06Y3iV8TM6d93Pyd+XpeK",
	"Bd0f3Gh3H7tIjyfEBBe56VZuBy2HUzhcXbuNj5C2iC4veXKIQyjUW58a9b9OoxY372nUariG7Qb5PiLF",
	"hK99xmf4dyfBlD+TYD6TYD6TYD6TYP49STBwZyILkhkzFFPZeJyJ+lBRMNgPdg0kUnCXaiVvTMZNg/Ee",
	"tVp/bGqVR7jOjKblzFxZTbOTeHnf1SpOZ69pTX3Ylgdmu5nSrN6qQvqVh11zUI93ubyoJKbFWnbk1DKT",
	"vrJrjQa7aS+xnPQXied+d9lYlemkX3Mavfi+sepqzf0iNR1N1839Ao17TAYllmC0ZRt8lZNL+1nvbqaD",
	"B00eVUy5mFnJyTjj9Rp8LKDWqpxs9cuJ5r6Rbu7LpKZrS7VYyzb6k0yj30k3951Uo7dFYNzcs3OBx25c",
	"eWxkn528pY7qmqJnNLU63D/rw/0kudQUvUnk1HD9rDc3MjsLfjAnqW5C0QdsP4b62N0qe2PznFJTqpPB",
	"il5JTsbdpYL4vjaT8XSpVivO836pN/VBprmqpZrVhjMZ1fXmqpya9BuZVknVmvuu1hoNUs2+ytOZldQQ",
	"8f3peUNGmbWcHBZcONiTZJ4yOVCY7HpGYbu2n+YPppkxEsTUC87rfrnude+zS3lVSbSKTzCNnnvZh2I7",
	"7/SmEziMrR+KapymFDU73MmtTGXYqbe7NLeOv+ZylpJM1At9Z5hb95QmtmKJVUUv1O1xK7sA8WTiqd/t",
	"4Go2V8rtp83881Zv9LrL1GO7Qluv6eeionfKvSRQYd0hRjWfz+k6tftbMz0vWFvAkx/mFiTL/5Ya0lce",
	"H+Ldcjw1TXaHSrk+bCaNZDfVxf11xumWE+uGnjenj0aiOWruGyhhKWWzC+K7fndQf+j1p31V62R6WjcL",
	"S+q4EV87g0G+rK4zJfmx0lCry1bzUU31ykswKA3Lw0SlDPT4UQ0Z5K1OPLNW1sNRN1FHw30l06qoT93V",
	"cjtIPTSA3nydrOrp5qi8nwyWnVZZS4/304dxqrkfJBPxVnm4n2jdhlyq9JVVd9KLs3FpZ5g0MRhOkt2q",
	"OexV1foknjBGuJ4ZOAm7WfSrIfV9NzFJg3jNmay78+G+kJ4O6zVlVR93k912o7rcDfXMeDCgFVDu9oej",
	"fEIdM4UpY/nVEHWUMUEy78gosZKr+cS0mNkourJRcMcCWI1zFaVVu8+Nc0p86fQUa1a6v8tWF/Q53VPq",
	"Vk5LGzvjfrAB69jT2GhSOih1dvoU19ZKvZTrmGAG661ttrcaPaaKvfxKW0+7xUVKvR8k7mlMjpNNLJEY",
	"2fpIG2zuuxVyn5bLYG3lBzAZ6w3VhV0ChefHsppfFDfP7ddh9kHvPKd6llEZLYb2fQOi+CCODAtmyzH4",
	"FJvJ9F6vDuLx5rja3yzajfWkOl1vrXEOKvWcA1bPsQSNxZoJZ9HvVlOwNEjjdbNcL1fSCfr6kF8WJ4TM",
	"CgO9iGsk3q0Ac2jH7pdPi1W2v1dbOFvYtleWDZztRqvt9quK2aiNgLwwBoX2/hXMei1Lq8bAfS+faNip",
	"5b57L2e0SjvZz1W7aaNrLMmgaXWnNF9bTO1CvaoMG/dpPU7Tqemm3nsqdTNxqN/H9nUrk0m/qhoY517t",
	"5JLu6GTwoJVi7f1umyZbW9/GUqlMo74HZNyuFstWvzRPw31v/FCUayRTe0wrcnfW3tOHV3k97E+Tk7bt",
	"3Cutbu2pg/Y5TWtMi1tkkSRQ7x8fN7b2XFk0tExvkNU22f0SxTqTvhxX+xslV1KeHpdVbeWUOrQ4cXbl",
	"SqxqD1LDMSo95nD1sa7pyWGmuwJdvW921qsCniUf8gMt95DbbnuJbqtVVPtDU1HUHkhU4mm0r2XgpN9K",
	"1NJkR4G8zVuxcjyZc7LqsEX1XttU5mCVy5Uf8rOJ2k7B3MhaqIN9fFZvlw3VGQ26Os7UsFGsZo3WZGMb",
	"8yHqjevpcYuuGuX7zXKB005n3tKg3MfyUBtm95PsUJOTD218PxwP+8XCZl+j+nyjTSopZZGO2etEYh17",
	"7vd6nbiualo2u8Db3uPrqtmp6Wu83prDYl/XbRNqq2pc7owGNFFPknSrucHPuF3JWRrGVmv0UNxscSOV",
	"UlvJpZPf0jhUzadYrZHSqr02SqFxIl3upw2zgtFUfp7KfWQWt+3pftOD1aXWgONxf7/IvNrNTtM2t7Sm",
	"VhYTvQ4UnIonYNfo3rV65mvhvqba68J97PGZNtLF7qATcY1JL1/1AQILWu9MNw21aG26hJi6lqiIHtvc",
	"9pzbGo+hWJDaFiYSwJKb7EXEWD6nCFF7+XovWAeOZPDJgaY5EsKKZqs8E5InpXqOBzdYjeYieE0Uw4R8",
	"cTf7C6rcgLYxWhsWjimaYaszxbDgTAcIz8z1YmaYEAMTzRRD1w08YwazSaHqN7eDRxUbFcllS0AkGUIs",
	"eZ/xo26RpkkylOa2Nkeaxv5KHKwsLQMbNtGcuxc8MWyJndE0NM3NvyWGbSmQT6AbGFHDkhAlEuFOER7A",
	"YheiwYPX6B2nkoHq5oR+zI3AU0p4buEGaEiduednOib7ZRaEkAcd2VDZ1fFPbsexdxxLbCsEHbv+HcwB",
	"Yncg5pf4bvhBo5KbjuPtVzUgkbBBeWoiQPiFId9hBE/KnSOoqeS94FcMPNeQ8pPA92a5AHVwxKEtoku+",
	"bwJ0yPNGJKBZEKiOBHeIUPK7b8Pdl3cC4Q2VADboElpRySY2J3O6RETSIcCE7d6RlmADg+d4L+TnhiUj",
	"Vf2o+8wD/WGaC7C3CbQkxYKcLQGNSKrBEelwgAMCmRbaIA0uIPnvUARjjirESOT1BDhx1IU/cBjzUgAP",
	"nPPkHxgc+IIF23VPiPAieEbBhnnIHUuFdu1AaBxMjMrwH0fYvOBjleQROoeAnpfMGojsvQMiCFNoYaD1",
	"oLWB1rUkuxtxgfCJXEiHo4PLcajhyidFA0j/vfddwJKN4c6ECpNKIiXQUBTbsqAavGgQGEktgAmCmLrf",
	"AKwKaczFOVTZvTBOQy3nTqrNxUyIXyi7LgUQGJVMDQLCEMI0LCohKgEu97mn/b33hw1aMWys/tylYYPO",
	"5myaCzfmEwNQPTLSg0TgbPP33uAAA1mDDInmCKvSkb2/F4I29rLr4U9C0Y0mCP5xSQwFNUFBCr8Z98O2",
	"4PEgt/pAECbT34SXzFUUCbQQnhsfDLbYqi+M5Omod4Ej3RmW65qLfE2kEolkLpG/j0cjCFDvD3HxB0Ju",
	"nYzY8oUK/NvB7h78rYJ2IBs2PfLyQzGFH6p3vgQfr/ImrGNFeD2IkB4i78qElo4I4akiIlZoQou6XSgW",
	"miED7YZqlPKhSuYkM+iGb3tsM2pghkMs/d1fP3Me8iPqNdkwZK+0yrfLMEi5geQTQPmgI4TtkW+xBc4h",
	"JoK34faM+yEfEj3tAhKsIXrz2K3jYK9/iKjL+k/End833bfr4CDvxhyeJUChTt6BGpHjpQDLAo67icNB",
	"Qlu/nKx+OBPbAMS2flP9VwisgxC8/fhHoL4HBMczhsPglALO9nPQ7jn41UNS5XXqhf4J30PASH0DhWsl",
	"oZQILZSzbMg40905Xp8gJ+9bdNzYBcwMI+orl2TdCJ5b7yuEI53dmk2XDUiXRgioel6Sq3QiqHX+AQkg",
	"r2i2QaBiQTozDW7wB/8oA4IUBliNzNxf2LzheB0oXgslqZraFrUyZ/gSKK87h/bS1gGWGJFxpUkUTgmD",
	"MWQnlxmhArCBkQK061OEcbVQdDmp17uCJ4ejvwMbggANwQRheFxBAj4gcOlMiYm6bX3c/3qF9KqruEQj",
	"c6AjzZm53HyBNhB7/2CKjNBeohHNUIAGvbShaMREXk0qU1nCcEQxVFhcAk2DeAHfxmE2XFK88WE43Etm",
	"smxlDSAcuiKv3xfZspfX4YMOUvUIqpBqf5cKfM6AswBY+DYM2+Tla9+vV5FJtVIQQ8KLBkUbsLNlThHk",
	"WIB4cabtEgrKOmfi/lyzX6TU+/Uzweo8+cJ22fAW9GWFvVmb12MDT0n2sHV3ojDqPX59CTjnIPH8FUeC",
	"fyMv8zj62TUxD4WM178Vl+p95JYy3v7JCTy8RS/CQRTlX8cSoe1wU0soOr8HZzwR+1/Ajrfp9XZ27isG",
	"PifUYwnh+Yr+2sE7qQdhsKNHffTUk1RDsXWIqWsSh3fxuMBTAvNHQkBx9odgwePVCX3Fjrw+n80lsX/A",
	"OXKrDwGW4E548aSUpUomsKgjEQqwCiyVvGCGB4hSCO+kYlhPk5sOH0RTUfv6/bab813O2dWFgSesk9wZ",
	"kJ55OwMvNiGCYWGKtGjAF6bMMJ7wB5H4CAmoqgUJnwDbGlcbvO6PZ1LCY0vh08KdqSmIHl2znlx8c163",
	"HWDYpPwnSQzllVgaOvM+u102PQ36bb1MrBdGvCGlj2H6qNsM53DSv7MsDB75w2wvZJoburSew+uYzB2q",
	"h/Nf3Tiv130o6tYGLY2toGJfcRCTOYFerMYW83CLm0j9gnmE2DFsXjANsPvZ3LDuXnCYqiS20ON2ztVN",
	"ClPo927OS1oP25aIkPMBUUabzJzRHIa7Fncnm9ASxRU2NaRjPaQFNUDRBoabyt4f3oNjXKs+M7LFzqNH",
	"BHgby8LVc3ZWLi2M+TEhwI9wnp4u8vgj0YiOFMsgxpyGquBhzTBvZgp/M9XnT2EGV5Wh88qGG9WisCr1",
	"c/0orEL4bDdh9cHn1xQ06+BFvyzDP/dUB6cOp2OEEUWAQnLiY2FLCVd65GvEtlA412EG+exQi3wNpOTE",
	"jL8Voodw5Jm7wFDh7GBOz1xz+rbNhJvixz3efN9hLoBQy9Xru/duaPFPj91YRCjIr1XcqK57joOQ3XmJ",
	"1jOCFhjhxQxoi9kGaPbNuxXfSb5K9OMB2M5rJa+7x60bdqcseDOG7vuaXBHUU+NDpP+NCBHpMP8nVFys",
	"tmsiOh7eTDdwZxoEEq9TiQcC3uqEXxa/qGMCzy305KWUfQxTvK+5nHH7rbjNU47RYg+PLmupN12Pt9Yl",
	"lBLRjfeewAX0O0MjfHjYJgRSf4QnkkO7GbhTloDxCDcV0OeE5kzkcNXklgsO7oh7n9/HuMgbHvGf5RM+",
	"b3wIQL3A61swRapyhKgHyQVkwuY0OgtwIBz7B3Fb3b0Fy0uK2gV5eIYMYYfx8YEQDA4Rd1co9ta7viQb",
	"buXKN8jBUF3otFfFm89F/F5r0voZ29FviX5YWTyd5C0AnYPFa3sR6pbgbg4xgtH1eaW1jwCWBqGXYt3C",
	"XCjahBq6aJhxutyIXRyB1M1+co1ULiCgpLgfMgntsQ4xpaQDDBbcSPBt6wVz5xfk6T4kmE0R5WkQNmE2",
	"TlSqilncZnKAtwYTsUV2XMumyxfGDKTuQ6EYKpPPG4Tcfu2eWPI3Egm7hlrJA/7RP2SwI0RFJiePynL/",
	"HoWW7rn4bOIC3NPz715wbS7NgSY+RET0OGNAkYAk20hjrO+wRpTngFu2WAXzUUFkesFeJ2PJwOFhQW8y",
	"7mu51XUvBp/Swxnk3iKIcBO3xP8le2hh06VfPGHGlkJRXZIK6tJQTiTaC/Zya4HXcwVYkMljzSZoAzVH",
	"AqoKVWmDAPfyIQVR17+vQ12GFlkiU5IKWJV0m9AXzDATSH8wdhpDmH33h+upvJOkkiDFM6l6sgUdOKJ1",
	"6wtm69IlRFbQZxnlq3l9MBXAycGls3PLn0T57C9YByYRGUouUxBIce4qkKQABZ5s2PW8vmBiK0tGdUgP",
	"QgaYJsILoSd4pHcIEbJriEQ9xvXtDaK87HQ4Fxx/N4/DrxYh170NgTZDN7saztpNnSts/j43V55h+jt7",
	"it0zfPiW/N9fBlFIRp8vBv5moIyNCw2uBJqIv3VDfzMi+kU3c5V0jl2AbqSaQOenUII5iXFfX9zXu/p6",
	"okNw7E3pDmcS/pK4XRpbJi40w1jbZkCbiQrEEdmnUUlIwIM+4jXi9Ua/YHi3uHM1ty8Nz//sTuInWzbV",
	"qc7i5YyFOrVF+utJRuu3Ky6Qt5Jcgs6OQCKYSG0R2Su+LgLCUpIC//D96BbnhY32/xUbODwR0jI0eInP",
	"st/+i2bTJdoLIzrRIepaiiAbcLufyIPKJR/RtTs++oG8uxWOc1/Kl2kZc6SF38iZC/HaUmceTP+y5V4m",
	"kQxf45ikcs1rw0ddZRBYApaMqAUsxx1+E49wmxScxQ5A4AkVYmshEizYbinUkWOCV/s0Xz5kV/7eHaGB",
	"L6RDxnAIVAysEp+DilefaoBQHj48zo0whQtR7HtsAxIW3qqVigfv8l24TzXQzuHKMd2RV+bylyOfTvTI",
	"mPBpyQbiJqDMGDIkEFO3zsqfASwqtN5OD/CtHQ1eXQD+YTQd9u7O2f4NP8r4/YZhkfBZWGJzUUSYa6U7",
	"qetV1x2KO184P32JnGQnvpmFIR7E+x5SNHP0XrMxv3pN33tMF87J5YM36lcu73+k6aYsT0lqMJNThhJE",
	"PFHosLLB/t8EhGwNS32JhDsS3J+vJMsbWwwtyRsYftbjKu89b/DJqQvQ9gZJg27tVwL7DfZQCHKFg48s",
	"8Nl717QJtMKzuk8g7g38tRA/YSw+dAtjHu+ucTs7VNVVM0WNpg4JAQsY5Q0CAEWy5paACwYUkjMWPmtB",
	"otAi0J3VzcWCOxNglf2fW5H72O+33SGCS/CaWuFKkgERJaJsoJsnEXhALCrJNnW9TmxeD/xsfxaCVMhq",
	"3vGATS6cKoV2jUi8VFyiS8AmNwj05hX+Q7GWX8E4b1Xgr4N0ixWOfP9Q02jjg5t/FghF8FeVxZxCzYqe",
	"lgJTqJuGBSykOTMbH7LzfR8eVvX+wDHlZFUf9kQDhau+BgAiJDFjvwJNM7ZnW9ehioA3ybF8PUzhCqni",
	"PMWMIbRkBnMX0yTxq+xVfvMZ3pa3l0umf5JK1rYMLQwpJM9AhtoQaHao6c9hLj3ZMuSDJY2NlngAyJ8p",
	"degYHyiLC4R/XzDCKtxB1fNKMu2fYT8nNkAptNiS//9/4rF8ITYFsf23//1/vx7/FZvdffsej2YTP3wj",
	"/s///V9h0uTX+4GYpqpprTlvGPvnhpe+n7Ce0z6xocqj3wQ+RFesoJInQ83Ai9sKu04WPce2b+8D85n7",
	"5rLU8SxDF/d4naamMZZ2PIoFgSoKXrcWojAkyfcqcQaq33w/uXETXxsdYC90dr8ckrwtCGe+umHx3hwU",
	"7ujVeqlfhCqh5MqUarAgv3AZCsJLHUS11sduvB3SrjjsPvxtjd3cZmMeqOE/Siobr7GxxSfNkP3/5Nxd",
	"hSc/C3b67ec4hvW7+AMDAlK6547P72e4LnociabVF23fADMQXU006PpvD2FeFVAYY8MvhvvO7vIXs8MQ",
	"hDnFx5B9hHCo6Ds5DGcq720VceGS/kx5cQUTXOf8g3O5vEHaLo2DE9+PEqF8LNgP/XbUche4HbUuFSnb",
	"GAm3yKFWOXSfuqFyzfbNk7sxi7dP7s34xslB8Ny+kMgt5w4rpw6A/Aa07osWUC5KIxLQw1wVbMVMc96R",
	"ReRHqAb+g3rth14wwE6Q/7IxSwg0unRtC2GFMC1wjqgIEQOvnohZBy/4sANx7kAW/odUVAoWb7goKVi4",
	"rbqwKnTSWzs4FDy88qYIRYFNuFbM7p7/5CUSULC4seLZm/PbT4PmLW8v0wxudpC/81auJOWFbCngisTU",
	"MpgZenhdNiyZ/AIrQJhCbv+KuYCtIogvUC/vFhNKtMK1uDMRQyAUuHm/vxfQC0lMPrcxIKJoRL0wByHX",
	"9iCyBcMzgSm69uUFHojl+bWvCAUWvXJk3hMn7POT1Ehiy14w+o1askDFuofobCWo2BaiTo+hn2vkcL9L",
	"sA1RaDWC+0SZuw7xXCYyb8t5wIyzGgLN2J5XKhRdt27gjwNLu6mLkPcC/Sb5JfD9IWsz8vW75/b+wJxe",
	"39Aj/PhPottQOKWxuxqIKaWal7LDzCY3GEoOzUB5W0wEMOU0Zc2BInKIbeLaN0DTXrA3l/uIpdtgyDJ2",
	"CJI7SSoQCdE/yJEs2deu+NFtjaIYhZitwY/3glVoaoYjrClEJaBQ4nY5A4uFBRfiYjXgQIvPIdxXx+pV",
	"8ba+u5foC1YRMQFVlkxeaf7KT3IMb7j+Sv6pDJQ1xIJWEdUgbxh2Di3Go6FFBEjjd4m7uFcsA0wU+RpJ",
	"3cXvUsJlseQo9eVuCzUtxi0S99m9mHK9qqammxoUkOBbO5SUsc0twornutzgpV6t2rEGzQQL6Fn8jgge",
	"njTgPLRniYrWdL7s7UCc8dAMhz9GU4V0BDXtiZ2qFVIpdPJUfDIevyRkDuO+XHv38AdH7C/ARF82iS9u",
	"/6tQUFShqFUW4XypUHwO3X3BRMNEQdEu7PSXPLJ44eH21hNDmXQ88TZIfrYpHV8n9UvXOW8A+iMaydxy",
	"v7+ox6RfRHD7KVw4/Ofbj29+nBGjzCuVdRqTAm5KMaM+33NCbtrIWcmdxLssHxIgXfbzghHxeT8tuECE",
	"wkNkJCxlkhsfB0ZsEwm4xbAv2B0rPHacxxqEIFlz+EPGigXdgpAtlDAUwVufhIO+p/kvMA+mKxLvpOfZ",
	"n5fJp3UC0o8Q/fWXuj7p5PfTyRsZoWFUcvoGZSvwkiSw4NHp7PafeMH+6gKXjgIFB776JsuwKQwR4uAF",
	"M6kdg/iY0SX50sMkw5IOGWLuGodxOnAkHul5wcHnbd2KU4naFhYjyMkDuMZcmiMMYwsL8HR7oQHzeXjf",
	"uEPQTuQz+wuKDv0dBUACOdMF6qVgvGAgXBJuaRxPR+fRVgZsDE/y3ICbPs6bz7qJ5ZIxd4vgXRBfVh3c",
	"NvLhqb7HJ9F5if0Xr+LCbSThMZYLDCKASx/SCULfnf2NbOGvSrHRCG8fd4k+PS+RcJJjuD0pZ/Dewuct",
	"Fg6BVZFE6ZceA+FKH/DCAibVLOFFCd532yCXLpxT64OhOr/u6eqz9P4fQdOS7fHHGbIl/pQNXHqd1Q+I",
	"gzv1+ICD5ggc/rW4FfIowSelXJRtX74HopilH5/C7rcJu0vCiBlv4Lxm8Qbp0grc5U/Lmk8N9PfLM2AB",
	"HVJum12Iih2HfAnSbtv7gQdATPuyYDwtCBCpr764zIlks2/DtYCYCweuNwQxAPP1WgGEE1lVP8Ix94p0",
	"8UuVQ/zq+ECQ24j9E4n/SqLmS2gH9yqkHEELxWcJEGIoiN/lIZ2SKdtRzxfhOjHDKp990sRrTcXbCvNi",
	"Som7x3WDwqDnlhpe3+sXPBi/bS6ctE4/xGgO6afvMA2CBHXZK3f9woGifeo9fwZHfQdae5ZE7FIzz7ah",
	"acSnFPh9YAxzzrSIdxiubh3/wWL1Ol56GBlMg3PTDIUC5tdM3o+wJ02pP4S8wTk+9Y9/AbVcbHj7ltnh",
	"FXNKAlk87PV7lnm1vonwwsvGEITlawIbToPUkAzs5YVskaa9YBm6XQxcz/KxqEU0FXKj3GJORDyxcidJ",
	"hUOiyQsWqd3cErEJDLEWqMEbAfDzMhnHM+SP7f7Jn8QIPkTxP0Hoi0/6/tvbF+/zvB2qqW9xml3Es3da",
	"GMLnVBUdsC+ZFokb0fUfi63peP6XLnL2LuU/wlgRLOvLd/5fpP44JBXDi1TAVSs375hTAhb5hYypX6CH",
	"Ep/xNoqoip1EbjGW+diglXzIbP7n4XP6ly5y9lbgX5rDf2pRP6FFef4xiSB8aIrmVYYbmhbmHbtZU7pO",
	"r/9mCfSP15eib37qipV3+HADyPkzvttz7PyQI/cNNes2ofTvcN3+myXU7RrXx5LVwjodnT4b8bfKWHvB",
	"fnIFWkh2mgha8pceGDvgFfaOYVuSscWBnGAeK33BrTUFdxwGwwTPfhaPTIikV5/4O4pyT4RLS4BVTeyO",
	"7cKCL9j1HvrgBei5q5FfxRvpdydxqT/I+zLxLrO4X5GkZ/xL0vP+3erzn+0gKXKXxC2Y/jFnSRimv1Oc",
	"nz6N8ROOk9OpPj0o/2IPyok8//L92PT5qjdF+EQ+RjK3+VNOiKZ9bEZ9ixpbO9MKPv0sn36WT1X0r6+K",
	"/jbr/igHOVu5wcofcEP4g3qCTX+O4/1JCsMbSVxh+HR0bHxyz3+jD+Bya2lffajXe9vHfb2srjup7c4Q",
	"lQCRFNuyIKZcKnPv9Qt23ddPh+5B3rdRkcbstuVnTCmQcxas+H7Bp+H0i2Yurz71zvXrovHeOT9k23rb",
	"+fQw/0MNTuKG4T1SOTRk8Scq/kHeQMNbDNAAHn4oXt/2Or9fkiPJmxE6iGf/pEKTT7v2T6fMXSzwwrfI",
	"5ox8jfA3V94vwri9y/7vJnOXeM8DcHINS4T2q+iqR79CRr14SEN8wdVjvRuQFEAUINqvHtqF8E6BTK9W",
	"XXtb00SBiyh5UTSbqdSukLVEvrT7R/JRw9tjFm0PMpGPEPs7sINJbZOektInY/hUXt/BGC5VbTHK8j1D",
	"82EV7go1xD9F3yeG/4PSHg4i8WaXyFUiu8HzEU5kH8p4eFNRDXF4uN+EZj3cfdLqJ63+aa6USw8GhXmu",
	"+VjhahWOkrNSN2jpiBBe7T03LP5mo+UrNtAQXh98JTp/+hEcc16vVjD41nY7f/A6PtdP89N+ki4Hw0cE",
	"K9/Yp4fkb12TdKkh4dX2c6J9YtCkEq/9X0Tm9qGdYPDZT2Y0BScChBHTxactvHJWE1gUKbYGLO6ShAez",
	"9NjmERzfVqGOCQ8vr4neOO2nYvnuBU8MmyfOikUc94US0XXuJeI9pIslw3JTeJdgw8MQ7jv9RQNjqByD",
	"Ss7h7SqRrCepNo/58Ed3vDfZQwlVhCCGycJJZ8gPlA36Z/DjdEpYj+cvxbhP1MhAWXv+XN7nmpvSCtA0",
	"/sug+3y7SF5SXTvB8huJKuRL0ejviKyr7TqEddd7raa0hbK0hg5/ONr/GtT1KjEs8ba0/HFEW9aQwuY4",
	"Vkzz15IcqT7qnyVmv+BDZja0otx/CHeAoeQxemNYUogDglxFgzo74kdun8Hmv8fITi6KtywJwbk5hUc/",
	"q7RE9Pj28hFK3vVFJSCpCGjGQmKU73uR7AUv3M6Orr/n5EVjTzzzh61dgvQj+TGl34vCiseREfHmCNC+",
	"VzgfaNOiew1FeadMFWpwwSOVNvVn84tHlQ2L01lozDLcXd2D3rtzXKP441CRoAbPenqiQ6lAqNPaQ7Jn",
	"fj0fUPj5vV5S9N9iM+5Wj08LnYc5B93a3Tk2XXjr6lw2nXHbcOAGpNIR79wHNIMv4nmznQuo45vn7rvR",
	"x5euApx45n/o606qzb1WPgcpIfyUR/EoJFVQ0kgngoa7KIFGeNr7IUVckpicvPjYFvd6sm+OjV35iwbH",
	"9ldE2i6hxbBO7IvzVdkytoxe3TL5E1k+14yttDVsTWVbQbppAYX9qAW44gsWKRs2NXQhXgxdZ8fUmFot",
	"UjTc/kHUMDSEF1FpaWzhhsNcOGyxQV+wBdmXoo0w4O2B4c40COTVlhxGQDuQRaFdE8DEBhUpFWIXErVs",
	"dgEv+Ng0+MbMQ4+G+u5bhu+mIf/rhpeM5etc253hn+rY+q9Krsvd6T2lIdiY3l9vBWTD5j2rTh8gvaqE",
	"fGC+i9rDwNv9R9DKO/rvv/N3GvoGUpUvnnp6VS4cumAfnl/mTN779uLd9IOpED1XS3DFzInloRqQ8yZf",
	"0aAjCZl3ytnPVMI7SapRCWFCIVAlT4sQTd6ODc19ZkYgYw6Rg7LkNWzzfRUi3l4wDQgMj0+GnJVxTU/4",
	"uWICnwihcFREqlL07uadGoJfR/OEjpfpd36Yu/8Gs/jx4/8FAAD//9c48ODu6wAA",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	res := make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	for rawPath, rawFunc := range externalRef0.PathToRawSpec(path.Join(path.Dir(pathToFile), "https://raw.githubusercontent.com/unikorn-cloud/core/main/pkg/openapi/common.spec.yaml")) {
		if _, ok := res[rawPath]; ok {
			// it is not possible to compare functions in golang, so always overwrite the old value
		}
		res[rawPath] = rawFunc
	}
	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
