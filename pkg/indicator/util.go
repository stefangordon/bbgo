package indicator

import "github.com/c9s/bbgo/pkg/types"

type KLinePriceMapper func(k types.KLine) float64

func KLineOpenPriceMapper(k types.KLine) float64 {
	return k.Open.Float64()
}

func KLineClosePriceMapper(k types.KLine) float64 {
	return k.Close.Float64()
}

func KLineTypicalPriceMapper(k types.KLine) float64 {
	return (k.High.Float64() + k.Low.Float64() + k.Close.Float64()) / 3.
}

func MapKLinePrice(kLines []types.KLine, f KLinePriceMapper) []float64 {
	var prices = make([]float64, len(kLines))
	for index := 0; index < len(kLines); index++ {
		prices[index] = f(kLines[index])
	}
	return prices
}

type KLineWindowUpdater interface {
	OnKLineWindowUpdate(func(interval types.Interval, window types.KLineWindow))
}
