// Package generated provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.12.4 DO NOT EDIT.
package generated

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"H4sIAAAAAAAC/+x9eW/qur7oV4ny3tG+VxcoY4clbelSWlpogZaxcNhCJjFgSOzUTpiW1nd/8pCQQKC0",
	"a7197rD+agHHw8+/ecp33SC2QzDELtO/fdcdQIENXUjFpyklnoPMF/9L/p0JmUGR4yKC9W96UfMweveg",
	"JoZqlbuUntAR/8UB7kxP6BjYUP/mz6QndArfPUShqX9zqQcTOjNm0AZ8Znfj8KHMpQhP9R8/EjqhU4DR",
	"FvDFTm0Ca+GRGl/zyD7C4z65GYeSOTTck8BQY07tQA351OI/5GDI3FtiIijuxqAQuPCBw7UpfxPfEuxC",
	"LP4FjmMhQ5z0Ys74Br+Hlvi/FE70b/r/udjd/4X8lV2Iy5LLRg94S8yN5m9bc4kmN6EBef2pg0P9SKh9",
	"NkJw/9XbjdzpZ3YdRZsTu3+Rd3b+xuEa2I4F+b/q2u1N0r/5H4kzD6YeaDnQiDuX2pWmUEPb0W7sUSwy",
	"RWfAfp1crVbJCaF20qMWxAYx+SSRM0EbIEv/ps8JTI0tMp2y/wSGDVMGsfWE/u5ButG/6RQyh2AGRxyd",
	"/+TzDL10OntpWAhid4TMP68vM9f5K5BPgkI2n8ynDSM5Tl/lkpPrm0Imk5nk0+BaPkOhiSg03JFH0Z8z",
	"13XYP3LFf2TL/8iWPYwWhOIUc+a2RynYpAyS8hb/yJYJ8NxZ9h/ZsgEsawyMhVqfmHBkzIBlQTyFIxu6",
	"M2L+2coWLuN+/3NulF7qs5k7WOWbhcfiW3czmD0mr0iTGbiLm/1tdT6p3zeMWaUmn2cGceCfxIEYmf8h",
	"QPUfDiUTZMHzrz58WQ1x4SwOBSqYX5TietCAjAG64ShOISPWklPmBJqQAheaWqvV4AxqiUxIYzHEJQv4",
	"izAkuGP9mw4L12b+Jg2Tl9nJdTJ/A3LJ8ZWZTo5vxnB8mSmYYDzWEzqfho/eVGfjBwM1ULX8mm5Wnjvd",
	"dgWtUD/XLFTmBLUss8M/D3qFOf/82q5k6gvzrt2qsIrdXYFN5RJuqtR8XMg5Nvz7+sZElcuKVXTr7cqa",
	"Pw9LlcvKooyMdGHWydxu+rl+odmtsp5dpo3H7p2R7abb2XIWtKv5cSvjgrfyS2/eXb7a5Xoz67hGulAa",
	"o3Qe3F/nXzs3d+OHZrbRreXMO2tjtm/vx3czMN6W7432bN24rxV6HSfde6hOQLqPnktVcZbXXifXbWXu",
	"jIXL+rlmtfHW39bSTdbulVkrPbgdLG76RinzCrs320G6X2jPTQDShfrronnXXHSfxukybW4y5TaetY1t",
	"JVu7L9jQnuZbuIpb+LY57pTLvcfZcpB2SO/RyfZ7g9prq3rzXKpS0HtFDVRZDx5nOSN789SxBvev9rrd",
	"t9fLln3Dz1FtL6or86HaHmczbx3rdmAsCs+wVy+/dm+aHIbmo7UK7gSnUymPNu3x+jE7GuPr55oFUv1V",
	"GuTemftYKz7hNVgtKn3sPhrLRmkO1vPtspupWna/lsyW2uNSBmW7bpHVK0+kYZWrhcvHbD197dT6Nw1n",
	"kDW8RenxJXP7umZPNWbkM92VVRn0l/My3fYq9/COlG+yZdspNR96W9dbGbPbnnn1cv/adyawWq5mb+EU",
	"GA8z+Po+ab695QrN+t0mOWgYebO38JZl2r2utLzidfJqZMCrR5AttGjTazUBbU9qo9vnYsa7K45eboq9",
	"+YxtHp4aT9nywgN3nfSb/WY99+62l+aT+bS5aVbd5gh3Ogaz5i6o2NW3eb3+UrSr75k0rhbSmfunUeWy",
	"dnObazc79B1YjVs7v2BXyaVdHk2N+wwDjWW2aKD7m5fsbW1hXOYKC3CXKxUerU2vfVNoLczL0qi8cpz5",
	"a2fZ7/TTm6v792zdwd3J4i3vtV7s60nnLj+mrflDDz/W6vfX23wtO3qxavmn1qCI4HPTrhXn/cK6d/3W",
	"H3mlN1rA4+R1yy6OXpLWvNRtvLwU3+7e7tcgu26tx8Xqkvbfe9B7yFaWxUUpDcaXDplb7x170ewtG28F",
	"F7+9gmVh2ci+N4rTUr8za1V6b9t0sn89M7bNTmt619682oWbTedq/d59L6HNqjSbvlmNXPZpNZthOnle",
	"1y1au80X3hrWdlZ9yRi5u9L0atC7GjdGr1fF9PXDfEnf1m37atq5o8k5M3s3s3YL1auv3mi0bdXKL91u",
	"vf2Ot5naXbkCPYYuH6ropltKF0fEe2PmzKg/4cs5rNx1b0xcW5eM+fi1XXhnpft3kuwYpYflY3q0yoPS",
	"zLHM2vT68eEFdlqDGbhtPWc2mI0q6dJNsXhXhjem/Va/XJUeb73rammTbOfLBL41rW7rqes9ZB+q6JpN",
	"tsVyeXaJnmavb+tHu/BUL44QobfV7n2j9ZYzny+fGp23icluJ+3tNAdq5H7jZMfVmzoAhvtglzfVQe0G",
	"XtbWrevOelq/fHqEVw+mZ6TrD+XNLfVyJav2nr3dGrPGery9ex0RVOiTlrd+dqYPVm6NqpM6Llnv5fb7",
	"W616VfBai/SosXiaLu1HCG5eH5oAsHXhrfjccoAzMhalwbLenz+MyGCWT+eTT+25A7KoOr2vG1vYaWfL",
	"+fl74YaWSsVOedCdbLzcu3tbhFUb5rvTGR63l6DSro6dMrztbFrT/pPhPbymvOVrbY6sDrquGubmAeae",
	"x8CdKqY/WkKKJohr1Pqg95quPVTng4f+pt6eLQZ3/U0t+7qqb183jXY/XX+opQe9wby27RQG86Zdu1ts",
	"B/Puon5XXdTn3Vl9XlwP7vrbQbu76G/76Zpdnw9eiZ7QpxRgd6Q0a64YEKoUv5GQPFwe7nQM/ZsutIxv",
	"FxdKqnHl5kJqFBe+PnG+PA+L1hPyvFHk82titK/XJTSDYOZZrubOoEahBZcAu5oaCrCpNSp3JY050EAT",
	"JaOZNiFUm3jUnUGqmdAFyIrXCj3H/NebEXITJ80IOeS/lBnh7/pDM0KYb1IXFqYbMAzouNBsqi8PLcm2",
	"uGmp1s8A08YQYs1/TNz5ClmWNobaxLMmyLL4t2yDjRklmHjM2qSGuE88zQYbzSGWpXCHEY8aUExgE4xc",
	"QjXkMo25wPUkznDAWFAe5EdCB4YV3uX5Zg9iLc+BtGja3AaeAIsJC5c4EgRhiDH92z91CoGp//XjbIIC",
	"hhV3SUXNQszVyERAizFOOy4lHPn5acJkf+RcLly7FzPXtvRv32Pn55o5B5Ut9Wx5SUrL5nq4CVygTSix",
	"Bcw9xpVtvvYSIAuMLUlr7CtQ/ed33UTMscCmLo1KAV3EXApcQtmet4VdEHtDjEfyQKEzu9R//HU2bKNb",
	"jYezb0kozw/C4rhRSviR0MfAVIT6NTyClBIuGBBeAguZIwVwPSF/GUW35V/HmNOqeuR8Ji25+71YMebM",
	"zfDkE4A40clHNbGQOENCI1QRmxxtEsg0TFyBiQDhIQYBOSpeMkHQMiWGGgRPLGT8JLD8WY5ACew4wQq5",
	"M7EZBmwo3FYasDgtbjS4RsxlvxB6akl/c0wuDjDhQiqhecwDlrXR3Blimg0BZnxjG20GljC6RQGpCaFj",
	"ZJoQ/xyogmmOwIrTr2ZQaELsImAxzSTiNoNdBbfoULREFpxC9ssxbgWYZkKMoKmNN5riYkzhm4QX2HBp",
	"YACPyUF8a5GBQyy1CrV5hKfR7QveLEQAwFrxpRIgsoAAx2L8x+7YQ7xzN+wOrhHJBQLe4FjA5axS3NhU",
	"Khlfkiam/k3PpzPGxMgayWwmV0jmLzM3SXA5mSQzwMjmr0BunAXmjgdyEVpMtiGwuUAmFhRiBgh59FdC",
	"3Kv4ZgIM+J8g6UJgC//VX2df3lH9pvgBT5z+jAT4W0Hx16dgwU5LZDlGoFgsWLjQFaTwRck8hRhSZGiP",
	"7dqzJmhZc8BUcguEXUgxsFqQLiE9tcqZfIOJiUbyYzzrUCLCJUqfNyyA7F/GG4pY8zBcO9DgKqE8LjEM",
	"j1JoRpkCiIx0KcAMQeyqZwA2h5iPZJ5hQGhyGuYCwqWblFaZyJmQIH5+awZgMKE5FgSMMw+HUFdDrgYY",
	"XwYx5kl4z1cL9jUAL+CGCUQ36FL/pr8kC9mMntAXAu8z5nrFSLXZvbu1WmOLVMnKvanUbx133CJ2r/nS",
	"p/WnjXFfHL3yZ9yN/k2/L+kCx/mlIW5zrjn0HnrFsfd0i3H6/Y3Nr5Fp9maDeSE5aNfy5bxZoFX4NB5b",
	"jYeukSzgar3TZC/jq0WyNrt/pzevRVSYP2HzylrYi8dO1sbAWrHXlyc9ofM1i0XolKxe67pGnp9L2/fa",
	"a3Zs5Z5W2/IVbPWfZ0aLssX1ou81Qb2eL9i4672yx3zutVF5vr8tvL2Bx9mm1WpOuyVg11aDXmdVpMvM",
	"Qv9xPnvisO3B8RPctKAbT5nVVqOureBYW8CNxqCb0trytjXAP3Ki5SzE1BxvbCGDD+NCGbgaoPz2J5BC",
	"bEiBw+caYj6ZwHbG54KhBzUDYI6NQkC5RBNG/0bNpiiEyzmGptgXYYgNMSc0ZEiswsQtEw+bP0e6mLij",
	"CZ/mCN2GtDdo7lSlQJETitEvo+MO5po2h8gEYVPb6WbixPLhFyVPvyozpDe+cscpKJNJX97kcteXl/mk",
	"Q4y0cZ0xp2zimTRNx54zT3vYo3Nj6WayMAUch6WmhEwtyKWEWlLFeaK2yIMYpVWEouRu9IQuuAENeVKA",
	"YRAPu/6MahrfZhHfJZH//PmyZw9Gp4WQHBxoKFLrlrGaEsETNPXoKevwJ9wLh2vEeoAciCt3QkkOxkma",
	"EaqZ55KkiZhBlpBu+HkgNh2CsMuEUc88h3NkaHIrY0oocme2/GUCgetRqM4btr6/aokSG4jwtor8UWd3",
	"l/yrpPrKh3T9p6854jI4fcnhoSlNqxHmCj2WaWxGPIsLOYtzPKgRDBMcbJBqQiFinE9xrsMNISs6U6De",
	"hrVaFaT9Khht6AITuCAI6SOC20iAKpvO5pLpq2Qu086kv+UL3/LZgZ7QpbNGxn+XiCGCobRxHWgcCTif",
	"D2T/NKfh648SABAK5ZdOr1RQqYEKtxkwIdXP3ixf+Vnw4rjNKgEmtidMzWPquPLNfkWkSCfTSMzwO3b5",
	"O3b5O3b5O3b5O3b5vyR2CdcOopCNuBaUu0ynEzoyY0VBZ9tZ11D1JsW/NMs3pP9WJ5z3mA/Vx7pVfoSL",
	"Qm9wX5gY88FlP32/bVrlzevWsup292XccV7qOYu25mXWLt+u651quinkRTkzKFUue5tKod821o1eZz1o",
	"ZWb99jTz3G7OavN7t9+ubGqt9LY2b1r17TQ36A0W9e0UvbW4DMrMQG/FN/g+zs68Z7u5HHRurXGv7IxL",
	"hfk4m+a83oKPRdSY32cb7ftMfVvL17f3rGJbM7NUuay1+4Va+zVf377maq0VAm/1LT8XeGymjcfa5fPm",
	"hpq9qmXYBct86G6f7e62n51Zhl1n41x38WzXl2N+Fnzr9HPNjGF3+H6I+dhcGVuyfM6ZOXNTwIZdzvbf",
	"mjMDiX0t+2+DmflQ3jxvZ3bd7hTq80qu/lDb9HtVuz6/z/XbtULjzrTq26bV6HVy9bZpcZ5v5LpI7M++",
	"IWNUWIyz3aKCg9fP3rhcDhT76xYprhbe0+TWcQokwxy7uHnfzhat5tXlbDwvZxqlJ5hHz63L29LLzaY1",
	"6MNucnFbMtNuzjAvu+txo1DuvlZfmu71Iv1+fU2NbKZabG+614uWUcc0mZmX7WLVe2tcTkE6m3lqN1/x",
	"w+X13fV2UL95Xtm1VnOWe3wpu433/HPJsF/vW1lgwuqGkYebm2vbdr32yslPinQFdKXA+KHtWwgopJ+M",
	"TMdqUJ4740q61H6kbe4JfWfiWcKmoND1KBaen4irWVrz0gHgBz6lj4mIyYWbH2HD8kzhnRLxa98iUK4A",
	"NJGuAemW5osHJrlQ2jzsB/PgT7oDlA4n/evHIiZRWEjP3q9z5cXN7rvfVRxTQmUGmCbZjoICgxThCTkf",
	"AqdzCMGYeO7O6x9EMcObSOm7KK0KZ1txudDxgVh5odImdSC1EWPCSJOWogOpq/KbowHk7webNvnBINtt",
	"1gBYM4nmR9e4vj8V8yrCGBNiQYDlrflx6A9CzC05kB9YzULGfg4vMKyX3QE+AYG9YyMX2iw2qf3oc/wx",
	"iD2b21AyQ1lZT7qfKKHzW7agC7k1tZdOHnwBKAUbdRRx0nN2IWB3eF3S6ozLY5AULH6P2YoTBeEH9xEG",
	"uJ8VLxMt/qmrFcIT/hV/ba3g+j+Fs5HLOgdxYkHtubOayDg+XL/le2+0PX4jU5RZ5Nplgi2DBoXuyCEi",
	"JB79cgwYMmLvPxrgj731ivkiAzYHNx1x+x2CcObZAGscGYVfU0bC/HqIg50cRxsDYIKRAazTU8QhQey1",
	"7+U0nLj84OifuPEoQGPuXQZ/Tly5GBC5YuAJcSRy7dVfP1XOlOqnntAnwEbWZqSQf4qWEPsfEHClF1ZP",
	"6BYxgAV9D11Cd5DhepT/x7xxLI4YxIQlPwn+Y4zlw7UgaT4OY1vZwiVf2QIy7HiwosjQa2/i2NBuHTFI",
	"489GQRWbzzehkM2USh6/Yjz67/LQ9mSSGUsryLY9N4TtsgrqE7j+AZH4LtQd6n7gwtuNflahChX1Pdef",
	"FgSFTz/ABykHXJQMkblDNbl0HE2KY1fuThKjD9GTovI03PdJcfohB/gk9U+PEf0uBHe4Wjj2ltJaEEbT",
	"O6u9p5ZmEsOzIXaVXhif0nkEKJH59RjoH3wRDRienDAULBTpbnwujX+AE6SidwBrcC2D7lqOmpoDqLvR",
	"mAuwCajJhtggto1cF8KUVopLcD3r8FH6lLHj7+fdWuhyDq4uDjxxJTkHQHoW2YF+7pc0d2I2qgqo4ngB",
	"p6k/mCZGaMA0KWRiAuxZQsL41YJHuUT8tHDtWAZyd6k5Pgv9cF7mcn0yXrXjP2lyqIg9Wegg+0jVZPpx",
	"qo9FuFwvjl+EzaiD/Tyo7A+Z1WBDxkTuxwHk458uai6kDKqn1Yng2gHY5P+pwM9ju/2ihnAZk9LEXpiI",
	"ho8Bk8kTfKBKzo7kZCe0sScD53JeaMoEOL4/iqAL6MZPxOWTy0SZ4kuFaSJBjpvDfHLCoD+vhLVcKywN",
	"D3Mlw9bySGqJeuLA8vVwED8cRYr3RCWrnFOowlxtiOa/uNB2CAWU6yIeDtSh0IPBqv4XQpLvrRpK0k9E",
	"4vShjEapWoz4r8CyyOpg6zY0EfAn2eX3xSkAMbb+PmZ0IR1zmCuM0uSvYz9/TszwMVIfzxM6jugvRwm6",
	"iPfj2IeIvov5x2rX4lfldNlhqAyLzshKMtxQXFQjNFpkTVZYJD2qOPoQC3fNhngCxQFWj00ITQ1xnFiW",
	"W2gJW+XkJqU58/du7qSRw/cmUmVdoqmBQVZb+EIOZvUzIuImlE4wMSDBmTM3fayNtppBKhZyIBVJ58CT",
	"q6oUAAot4KIlH/IJpbOohT5zjeeDrceb2mEgBYf7GJ9Pql6H+RlnKmF7NBOjjcVlYBzsJC7/4pC4ovaG",
	"L9viL1adyB8k3ZoIIxcJ/1XU1E9JlmUDV/+mexTFEw63FEcBwzsFTrZnX54LzSBX8cCOjSuePnMz8Tbi",
	"bo9n33WcbRqr6PvS5NPQEo/uclWl9zWsw5xpGPgWbczu/GDRiKEpRng6AtZ0tASWd/Zu5XNaKNNndwC+",
	"88qdn4t37obVlEV/xth9n2JiknoqYoj2b4gxWdzw77G8ab5aMFlsdzbdwLVDGGR+XqEPApGYKC5LXNSu",
	"HOMceoqoOp/GFP9poVCr7EiV6rhLIvTx6LhOfNb1+GsdQynpp/zsCRSgP+nkZMc8nBKpv8ITWZAcCtfG",
	"DHAeoUJLIV+oYCLBVbNzLji6oxGf8HOMi33gmP1ZPhFyCscA1A/yfARTZBo7iPqQnEIubPYjPABHQjp/",
	"MFWn9hEs9908khUkjsnDA2SIO0yID8RgcIy4O0Gx5971MdlwLlc+Qw7G6kHhEtOP2hgdah1+ymXMg9Jd",
	"IAcoalKqPVcxLEtmP35KQ1SNnWI7Kx11PhyJCuBdeDdwQMTWgUifku0xV1Uu7OmDPxsG2Ks7/X5mCunZ",
	"SmikhviQlP2MzOOtow5vPZwhekbqZs0fHkoJPb/JUBSMwdJqqjiI7i97cLSmX2HmzyZufpdCemC4RrJg",
	"4zidi2wYLWheAaa6OpkRJmYCFyb58FgbD8pC588uJAOrn1jIz9iNtXE9SoWRKz0/yhQLagC0iig7tKRL",
	"TQ3ya7+HegcvMFnhoa552EUWt3NDm0VMo9Ag2BD5BMotF/hXVXDTgjSlVYTvFcuZZYWQSuQY4uEu0Rjh",
	"6VCPlJ/LUlF+oR6D3FjFGnI1Kby5cNGG4TTloS6TQuQ5hljMAixGomuKfR4sqw5vesI3B7CqvxczDnEY",
	"NEp3EKvfQSc6jdgjUJcYeGoR08aQz+tQwuUiNFNDXHFFCZXYYHhO4fUb6hqa7NVWRauwdlvdaBzBJYcb",
	"YuU0VNVZQT3Wx1wtQhkBWp0gypai/7N5TTgi82HEg48LyY8vcuQg4/wEMw4zi7P4cKjVWgwL3guPnV44",
	"VOR+OgYVHXtWJCqiz58IekZtjEgagAx1yhBnKAFRKiha5EPoR5VjFTc6/C0mOD6BJIgUnoCdiPudhBgf",
	"cVyliDVuTkFpZ8D40JEen1AQ3e/DFnemA9v31FIHpnd42ftWIZONT7yR2aEHTicQafvCPCuGNqO1BrEW",
	"gAO4xhZN1orzeocSV4+KPYQ1xoWHyUKWjWCvFmCucJ3u5kbYhVPpddvlwMZogcLJ6bslUvHGeDhof+qY",
	"auSJucJ5kfsTPZLVYXodEiJrDDWHQgaxq6p3wzJVxj0+5tWhtRPRq9s/Y+Q+4jhkXO+gg/OQMAqFDVCC",
	"YWMiSo32Wf2uH9L3U4kUfx2IIclzdi3+9lon7Xd1+utH4rzF9xI29tfd//mv+JDHKC5LoyRDCZW7lBbo",
	"o0Hvi6HY8FDfSy75MDIqOxZ+j8nm3Pl4ZJzw164Zaph15JyCnfujfuXy0Ys7I0lH02rKmINIhDGDlQn/",
	"3wGMrQjlmmGsWal+jrMqFEGSFYZU8wfGn3W3ymfPG+0JdgTa/iCt06z8SmB/wAuLURYYGNSRxz67pscg",
	"jfcI7EHcH/hrIb5H8iF0i+OMQf7RCTUkcHwcVUN2mYYij1hE9v4NpqbRHIx/P0NJ4VoENDyK3E2La6Kq",
	"15VgzdEk79jAk6r2VQBgfhbBWGT0q0uOCRdZZHUYlCop3hT5skOtUDm275JJqQ66ScMinpkidOr3uVtm",
	"LyLP66HUaV8wfWFOv+Rgd6PiJ5kaj/CExMv9jpwyKDHXii8VX+tmQR2BaGCGOMqJnh8TYMCdfSoaDlnW",
	"EPtzqe4CKh+dkjWCLKVpRaYh9w8mphCZGvxpJP28tme5KOlCLIxofrwhNqFjkY3NbRDRDcNwmWqJAaZT",
	"CqfyYi2wUX4vmdGxS4uSHfzUXhJDbCLmANeYcR3TCqcUsZ1CoohOPDoGxgJi4ZJwkcupS4+Dlp7Ql5Ay",
	"CdJ0KpNK+3FR4CD9m55LpVM5rngCdyZQ6iK1gpaVFE4GVcGeNE4HUCu2Y0EJCbG1IFTNNzeNC/U3IVBK",
	"ZvQB0b3F92NupLq91zkrqH5PyD4mIUd9RDMPzO+KKVKF3B60rCd+qkZMUHivXV82nT5mbwbjLk61EPgh",
	"EPsCOOhimbn4yAVpcXrWbIDBVMAxrqC9ESlLBxTu3L0q+W6Iwy7hlCb8LhEvcSjcQonnwhhEA0PMMSsJ",
	"8S6ZQoOpaUpT3R4I1WrIoISRiavWCMZJ14lFVkMc7WagAuCa61EsR7C9fgdkok0QhskpBSKdUOrPYh6R",
	"jx/kWvl9lnbxjaBkRQJk52/mVO36iv0Qg13RyFj6+KRY48DGUad0QvZL9H3Smg3tsRip0koUiI+jt6qS",
	"ivct7/qpiKSVC3nxgbvOj8scYHDRQd1MBA++hrexrSB+JPR8OvPx07FVWD8SeuGcpU/1ZAqLUmG8xAvR",
	"f/4lGuKI8odjlOR7zURdx2GIJQrYF8KOQdZ//8Lm+MlCr2i4OP7egx8H95Q5YuiGQy/R+jtrs/N3/+xl",
	"5dO5jx8+bLcnnrz5+MmDloZ/N34c470X38Mff/xmxX8bKxYqxu5FM/+Mx4TdkIv4F8EID4B3nPL3qF35",
	"dmTYwIyhfS+G9BuHL4z5FBs43rf4Rzy73rMKwvuPkL86RqgQ91/JC349OV7ElpU+QNHpSCuWnjXAGDGQ",
	"AEJgeXJxmZCe4MB3F+H4Q+y3OPMpzk+sFOVyWvO2WNKEEWYTF0btA5f4QbMh7rx9LPD3yjcDX1VgqX9C",
	"uIc/FA3rS7I+3Mz5v5uE/yXs4mzU8/PXk8dqhV6IZbEQc9tPbDjghp9QD1WfzEAv9Itq4hIm/B6jSpCE",
	"OexnkWqvQPJLCHakx/W/TkP5H42mRwvZPtJb/HCmJu/JRxvRwlOh8xDbwHG40S3EuGrNHy7wikd+l3D7",
	"SWHvClnWEHOjyTQls40mQMoUPpn1HrR89HkuN9iCuIvsA6lUGY/BGHXDJRqyHUuclwsAUbczCWZg/58o",
	"8Auk9hMUNv1NWD+nLp5tKWoYrnah/HOsxCNX/CW7MfJCjrMMRvFErIX4X0RF/B9mLipSvPiuXm2p7EfR",
	"c+MYgglJrbLOlDtCNJPlrOoIqt2JGc9BtofQKzY/MitikCXIavtX4kf+4ycPegD//czot7T9CWnr2+Ya",
	"Q3gatExQaRfEsuIs8zMl6mkKOEOw/parX5KriQ8fPHiR8IeumwhefN1lc4gYX/LffCCOz+Ow/7U8Nv9d",
	"2O254liFl50TRaaxjHq/3lS6TgNWq9ijSA3zi3KHmMIpYi4Mkh5AXIHDakZ24WmP43Sk6lq4iOkQi8gz",
	"YQyNrY3ou29QqCqiVlDDcMfKFWxgxHd0pklzsD2W8DNyVC0doapsWkmbnzRyGns1v18KTh3pfv/beXWC",
	"EI4nVIdC8/6LykPE4Ls6U5p6sTRLaID5BQpCQxTayBArBHnyxpBi6MJAiUjI+IftWMhA/JGoIzZacjbE",
	"+xgWi8rPHIGBZQVJ4L/KCvdP+SXMPOj6/ltj+CWWeEmYrEyZ307whnOVehZ2nP/BvhTLPYoCX7LT994M",
	"f6gaZM9xy++9DlKgwxmXGvNuvd/G/Uf4u05GGkslVQ84XZRWfpbHXnxX/520/qUNz/wmGwKl44JXYRlv",
	"+jguWegQH+mw67+uxwDMALJXUZBIGBRqqWInkfmmXkMoOkJ4XIdRMoDKGJf6kn3NE+ETlPqr/28mh/8e",
	"voy/yQBUaP8VfSZoXXiGNi9f9iGzsoS2cqL3LhcmQyzfChN4+i2EF4HCYmtLBMJvJT6pa4fWDr/q6tdo",
	"000BhK9oKtHXs/xWUz6tcx/LhT6Z+apezh3h2bKnzFE8egkymaM9JjhXjk4EGMfjo43m/BwHB1AXGZ4F",
	"qFDJ4a6ZYpBhDna1CaKFo38TMuXx5al0H3qPtFxkozL8ZcLrUFf9nUUTLuWSFC8JBdjvBlMiGEPDHeK9",
	"Fu++D8SvkxVFK37nj1gakTZlN1vcS0r/QqQ69k3QPxJ6Toqow0oLVeIxBsbCt2dUmxkuStUL4bVO8zl1",
	"tsA6fOHluXQS86TMMd4h63y1YB838YyUip12JWBNVDmIstjQ6wD33udX7bUPHM1DHHiaIU0IJV714d+5",
	"JeTLzfY1HHYSDar8iF+5/cjbKX8Nb9qDvkjgi0GkiQtDb9WdIZcdvqk3uJOEBjQTAYtMuY4Xrkkc4il0",
	"w5ZQpFQlEYg70QFAUVkYc3dxB9+/xSWduCU1R4Sg/RSpSNKi7RcoiMx7rmJOxevwPTcccpAvDSVUEM+B",
	"E0pkAsYagi3oV54KCf1HEDYxo2fdP1EQz4g1B33MEW1av2L1hZvAHlh7H/EOtdVd985Dn2GnWUkdYtOR",
	"ArBDgXPAQuOBGxE1O7xTReDRmthdK6Z9qTPEEbETLv86LCP1C8HEO2V3jbEk65fWzU7mSfETFR/7LwjZ",
	"9Y4QbSiUO13TuPA7WoEmbCX+TLRRWug9GUx1XPSY3JdglmNKVpxeVbLV/ttALLLSVuK1gmPh/aLA4D9a",
	"EVY3xNJT7LnEljKD2DY/psXVVOUZltm0LiEWwtOENiMruBQwl2YeJu4QU8iflGVJQJQb+U3Rwq8pV7gm",
	"XuTNV8HElQ005S40l3I7zxziXRFSLHUep6F2UM38SRoK1zMfC6acZsXRN/b9C+3DXy84/P5YxwUx4qyd",
	"U57K//ugt9eHgv0L8x2VyB1/91+51YOX2fzc7XwyxkSQaVz4etxJXhtUqgVtOWRjS/XsUYC3oz7zlpK8",
	"inXvqejB24Z32QIbTcqRfW55oDulNK3iaggzFwJT8yWzLCPYFR2G9PFQjZSwHIIucsCPxu64xKHIGGI3",
	"woR93hNzVs6JfIGiWC/eY+zx+IVMo+TfzSelbljv8Rm5H7Q7PEzql5H1jx//LwAA///ZhkHAXZcAAA==",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
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
	var res = make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	var resolvePath = PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		var pathToFile = url.String()
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
